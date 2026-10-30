package omni

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/siderolabs/go-api-signature/pkg/pgp"
	"github.com/siderolabs/go-api-signature/pkg/serviceaccount"
)

type pendingAccount struct {
	Name    string    `json:"name"`
	Expires time.Time `json:"expires"`
}

func (b *backend) credsPath() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("role"),
		Fields:  map[string]*framework.FieldSchema{"role": {Type: framework.TypeString}},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.issueKey,
		},
		HelpSynopsis: "Issue an entity-bound, non-renewable PGP key with a revocable Omni account.",
	}
}

func (b *backend) issuanceInputs(ctx context.Context, req *logical.Request, d *framework.FieldData) (config, role, error) {
	var cfg config
	var r role
	if !validID.MatchString(req.EntityID) {
		return cfg, r, errors.New("An authenticated OpenBao identity entity is required")
	}
	for field, value := range req.Data {
		if field != "role" || value != d.Get("role") {
			return cfg, r, errors.New("Credential permissions and TTL are fixed by the role")
		}
	}
	ok, err := load(ctx, req.Storage, "config", &cfg)
	if err != nil || !ok {
		return cfg, r, errors.New("Omni configuration is unavailable")
	}
	ok, err = load(ctx, req.Storage, "roles/"+d.Get("role").(string), &r)
	if err != nil || !ok {
		return cfg, r, errors.New("Issuance role is unavailable")
	}
	return cfg, r, nil
}

func (b *backend) issueKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	cfg, r, err := b.issuanceInputs(ctx, req, d)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if r.OmniRole == "" {
		return logical.ErrorResponse("This role does not issue Omni keys"), nil
	}
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, errors.New("Key name generation failed")
	}
	name := "bao-" + req.EntityID + "-" + hex.EncodeToString(suffix[:])
	ttl := time.Duration(r.TTL) * time.Second
	started := b.now().UTC().Truncate(time.Second)
	key, err := pgp.GenerateKey(name, "OpenBao leased Omni key", name+"@serviceaccount.omni.sidero.dev", ttl)
	if err != nil {
		return nil, errors.New("PGP generation failed")
	}
	publicKey, err := key.ArmorPublic()
	if err != nil {
		return nil, errors.New("PGP public key encoding failed")
	}
	encodedKey, err := serviceaccount.Encode(name, key)
	if err != nil {
		return nil, errors.New("PGP private key encoding failed")
	}
	c, err := b.connect(cfg)
	if err != nil {
		return nil, errRemote
	}
	defer c.close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pending := pendingAccount{Name: name, Expires: started.Add(ttl)}
	// Persist only cleanup metadata before the RPC. Ambiguous RPC failures and
	// a crash before OpenBao registers the lease must not strand accounts.
	if err := save(ctx, req.Storage, "accounts/"+name, pending); err != nil {
		return nil, err
	}
	if err := c.create(ctx, name, publicKey, r.OmniRole); err != nil {
		b.cleanupFailedIssue(req.Storage, c, pending)
		return nil, errRemote
	}
	remaining := pending.Expires.Sub(b.now()) - 2*time.Second
	if remaining <= 0 {
		b.cleanupFailedIssue(req.Storage, c, pending)
		return nil, errors.New("Credential expired during issuance")
	}
	response := b.Secret("omni_key").Response(map[string]any{
		"endpoint": cfg.Endpoint, "service_account_key": encodedKey,
		"service_account": name, "expires_at": pending.Expires.Format(time.RFC3339),
	}, map[string]any{"account": name})
	response.Secret.TTL = remaining
	return response, nil
}

func (b *backend) cleanupFailedIssue(storage logical.Storage, c upstream, pending pendingAccount) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pending.Expires = b.now()
	if save(ctx, storage, "accounts/"+pending.Name, pending) != nil {
		return
	}
	if c.destroy(ctx, pending.Name) == nil {
		_ = remove(ctx, storage, "accounts/"+pending.Name)
	}
}

func (b *backend) revokeKey(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	name, ok := req.Secret.InternalData["account"].(string)
	if !ok || !strings.HasPrefix(name, "bao-") || strings.ContainsAny(name, "/\r\n") {
		return nil, errors.New("Invalid account cleanup metadata")
	}
	return nil, b.destroyAccount(ctx, req.Storage, name)
}

func (b *backend) destroyAccount(ctx context.Context, storage logical.Storage, name string) error {
	var pending pendingAccount
	ok, err := load(ctx, storage, "accounts/"+name, &pending)
	if err != nil || !ok {
		return err
	}
	var cfg config
	ok, err = load(ctx, storage, "config", &cfg)
	if err != nil || !ok {
		return errors.New("Omni configuration is required to revoke outstanding keys")
	}
	c, err := b.connect(cfg)
	if err != nil {
		return errRemote
	}
	defer c.close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if c.destroy(ctx, name) != nil {
		return errRemote
	}
	return remove(ctx, storage, "accounts/"+name)
}

func (b *backend) cleanupExpired(ctx context.Context, req *logical.Request) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	names, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		return errStorage
	}
	var failed bool
	for _, name := range names {
		var pending pendingAccount
		ok, err := load(ctx, req.Storage, "accounts/"+name, &pending)
		if err != nil {
			failed = true
			continue
		}
		if ok && !pending.Expires.After(b.now()) {
			if b.destroyAccount(ctx, req.Storage, name) != nil {
				failed = true
			}
		}
	}
	if failed {
		return errors.New("Some expired Omni accounts could not be cleaned up; retry required")
	}
	return nil
}
