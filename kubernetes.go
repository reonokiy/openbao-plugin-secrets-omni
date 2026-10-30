package omni

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"k8s.io/client-go/tools/clientcmd"
)

func (b *backend) kubeconfigPath() *framework.Path {
	return &framework.Path{
		Pattern: "kubeconfig/" + framework.GenericNameRegex("role"),
		Fields:  map[string]*framework.FieldSchema{"role": {Type: framework.TypeString}},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.issueJWT,
		},
		HelpSynopsis: "Issue an entity-bound Omni Kubernetes proxy JWT; revocation cannot invalidate an issued JWT.",
	}
}

func (b *backend) issueJWT(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	cfg, r, err := b.issuanceInputs(ctx, req, d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if r.Cluster == "" {
		return logical.ErrorResponse("This role does not issue Kubernetes tokens"), nil
	}
	c, err := b.connect(cfg)
	if err != nil {
		return nil, errRemote
	}
	defer c.close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	user := "openbao:" + req.EntityID
	started := b.now().UTC().Truncate(time.Second)
	ttl := time.Duration(r.TTL) * time.Second
	raw, err := c.kubeconfig(ctx, r.Cluster, user, r.Groups, ttl)
	if err != nil {
		return nil, errRemote
	}
	data, expires, err := parseKubeconfig(raw, r, user, started, ttl)
	if err != nil {
		return nil, errors.New("Omni returned an invalid Kubernetes credential; diagnostics withheld")
	}
	remaining := expires.Sub(b.now()) - 2*time.Second
	if remaining <= 0 {
		return nil, errors.New("Kubernetes credential expired during issuance")
	}
	response := b.Secret("kubernetes_jwt").Response(data, nil)
	response.Secret.TTL = remaining
	response.AddWarning("Revocation stops new issuance; this Omni JWT remains valid until expires_at.")
	return response, nil
}

func parseKubeconfig(raw []byte, r role, user string, started time.Time, ttl time.Duration) (map[string]any, time.Time, error) {
	invalid := errors.New("Invalid upstream kubeconfig")
	cfg, err := clientcmd.Load(raw)
	if err != nil || len(cfg.Contexts) != 1 || len(cfg.AuthInfos) != 1 || len(cfg.Clusters) != 1 {
		return nil, time.Time{}, invalid
	}
	context := cfg.Contexts[cfg.CurrentContext]
	if context == nil {
		return nil, time.Time{}, invalid
	}
	auth, cluster := cfg.AuthInfos[context.AuthInfo], cfg.Clusters[context.Cluster]
	if auth == nil || cluster == nil || !validEndpoint(cluster.Server) || cluster.InsecureSkipTLSVerify ||
		auth.Token == "" || auth.Exec != nil || auth.AuthProvider != nil ||
		auth.ClientKey != "" || len(auth.ClientKeyData) != 0 || auth.TokenFile != "" {
		return nil, time.Time{}, invalid
	}
	parts := strings.Split(auth.Token, ".")
	if len(parts) != 3 {
		return nil, time.Time{}, invalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, time.Time{}, invalid
	}
	var claims struct {
		Subject string   `json:"sub"`
		Cluster string   `json:"cluster"`
		Groups  []string `json:"groups"`
		Expires int64    `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil, time.Time{}, invalid
	}
	expires := time.Unix(claims.Expires, 0).UTC()
	groups, expected := slices.Clone(claims.Groups), slices.Clone(r.Groups)
	slices.Sort(groups)
	slices.Sort(expected)
	// The response arrives over the authenticated Omni TLS channel. Validate
	// returned scope/lifetime; signature verification belongs to Omni's proxy.
	if claims.Subject != user || claims.Cluster != r.Cluster || !slices.Equal(groups, expected) ||
		!expires.After(started) || expires.After(started.Add(ttl+5*time.Second)) {
		return nil, time.Time{}, invalid
	}
	return map[string]any{
		"server": cluster.Server, "certificate_authority_data": base64.StdEncoding.EncodeToString(cluster.CertificateAuthorityData),
		"cluster": r.Cluster, "token": auth.Token, "expires_at": expires.Format(time.RFC3339),
	}, expires, nil
}

func (b *backend) revokeJWT(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
	// Omni v1.12.2 has no individual JWT revocation API. Never imply that
	// deleting an unrelated PGP account invalidates these bearer tokens.
	return nil, nil
}
