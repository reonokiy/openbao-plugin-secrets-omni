package omni

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/siderolabs/go-api-signature/pkg/pgp"
	"github.com/siderolabs/go-api-signature/pkg/serviceaccount"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const testEntity = "11111111-2222-4333-8444-555555555555"

type fakeOmni struct {
	mu             sync.Mutex
	accounts       map[string]string
	failCreate     bool
	failDestroy    bool
	failKubernetes bool
	kubernetesTTL  time.Duration
	lastUser       string
	lastGroups     []string
}

func (f *fakeOmni) create(_ context.Context, name, publicKey, role string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts[name] = publicKey
	if f.failCreate {
		return errors.New("ambiguous RPC failure")
	}
	if role != "Operator" {
		return errors.New("unexpected role")
	}
	return nil
}

func (f *fakeOmni) destroy(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDestroy {
		return errors.New("temporary upstream outage")
	}
	delete(f.accounts, name)
	return nil
}

func (f *fakeOmni) kubeconfig(_ context.Context, cluster, user string, groups []string, ttl time.Duration) ([]byte, error) {
	if f.failKubernetes {
		return nil, errors.New("upstream diagnostics must not escape")
	}
	f.lastUser, f.lastGroups, f.kubernetesTTL = user, groups, ttl
	return testKubeconfig(cluster, user, groups, time.Now().Add(ttl)), nil
}

func (*fakeOmni) close() {}

func testKubeconfig(cluster, user string, groups []string, expires time.Time) []byte {
	claims, _ := json.Marshal(map[string]any{
		"cluster": cluster, "sub": user, "groups": groups, "exp": expires.Unix(),
	})
	signature := make([]byte, 32)
	_, _ = rand.Read(signature)
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + "." + base64.RawURLEncoding.EncodeToString(signature)
	data, _ := clientcmd.Write(clientcmdapi.Config{
		CurrentContext: "test",
		Clusters:       map[string]*clientcmdapi.Cluster{"test": {Server: "https://kube.example.invalid"}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"test": {Token: token}},
		Contexts:       map[string]*clientcmdapi.Context{"test": {Cluster: "test", AuthInfo: "test", Namespace: "default"}},
	})
	return data
}

func testBackend(t *testing.T) (*backend, *logical.InmemStorage, *fakeOmni) {
	t.Helper()
	b := newBackend()
	storage := new(logical.InmemStorage)
	if b.Setup(context.Background(), &logical.BackendConfig{
		StorageView: storage, System: &logical.StaticSystemView{},
	}) != nil {
		t.Fatal("Backend setup failed")
	}
	f := &fakeOmni{accounts: map[string]string{}}
	b.connect = func(config) (upstream, error) { return f, nil }
	key, err := pgp.GenerateKey("issuer", "isolated test", "issuer@serviceaccount.omni.sidero.dev", time.Hour)
	if err != nil {
		t.Fatal("Test issuer generation failed")
	}
	encoded, err := serviceaccount.Encode("issuer", key)
	if err != nil {
		t.Fatal("Test issuer encoding failed")
	}
	testRequest(t, b, storage, logical.UpdateOperation, "config",
		map[string]any{"endpoint": "https://omni.example.invalid", "service_account_key": encoded}, false)
	testRequest(t, b, storage, logical.UpdateOperation, "roles/operator",
		map[string]any{"omni_role": "Operator", "cluster": "talos-default", "groups": []string{"openbao:operators"}, "ttl": 900}, false)
	return b, storage, f
}

func testRequest(t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]any, denied bool) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op, Path: path, Storage: s, EntityID: testEntity, Data: data,
	})
	isDenied := err != nil || (resp != nil && resp.IsError())
	if isDenied != denied {
		// Never dump a response or request: both may hold generated credentials.
		t.Fatalf("Unexpected request result: %s %s; denied=%t", op, path, isDenied)
	}
	return resp
}

func TestKeyLifecycle(t *testing.T) {
	b, s, f := testBackend(t)
	response := testRequest(t, b, s, logical.UpdateOperation, "creds/operator", nil, false)
	if response.Secret == nil || response.Secret.Renewable || response.Secret.TTL <= 0 || response.Secret.TTL > maxTTL {
		t.Fatal("Invalid key lease")
	}
	encoded, ok := response.Data["service_account_key"].(string)
	if !ok {
		t.Fatal("Missing encoded key")
	}
	sa, err := serviceaccount.Decode(encoded)
	if err != nil || sa.Key.Validate(pgp.WithMaxAllowedLifetime(maxTTL)) != nil {
		t.Fatal("Issued key has invalid format or cryptographic lifetime")
	}
	if !strings.HasPrefix(sa.Name, "bao-"+testEntity+"-") || len(f.accounts) != 1 {
		t.Fatal("Issued account is not bound to the authenticated entity")
	}
	// Persisted cleanup records and lease internal data must contain no key.
	for _, path := range []string{"accounts/" + sa.Name} {
		entry, err := s.Get(context.Background(), path)
		if err != nil || entry == nil || strings.Contains(string(entry.Value), encoded) ||
			strings.Contains(string(entry.Value), "PRIVATE KEY") {
			t.Fatal("Cleanup metadata contains a credential or is missing")
		}
	}
	metadata, _ := json.Marshal(response.Secret.InternalData)
	if strings.Contains(string(metadata), encoded) {
		t.Fatal("Lease internal data contains a credential")
	}
	for range 2 {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.RevokeOperation, Storage: s, Secret: response.Secret,
		})
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatal("Key revocation is not idempotent")
		}
	}
	if len(f.accounts) != 0 {
		t.Fatal("Revoked account still exists")
	}
}

func TestRoleAndEntityCannotBeOverridden(t *testing.T) {
	b, s, f := testBackend(t)
	for _, path := range []string{"creds/operator", "kubeconfig/operator"} {
		for _, field := range []string{"ttl", "endpoint", "entity_id", "user", "groups", "omni_role", "cluster", "role"} {
			testRequest(t, b, s, logical.UpdateOperation, path, map[string]any{field: "override"}, true)
		}
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: path, Storage: s,
		})
		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatal("Issuance accepted a token without an identity entity")
		}
		testRequest(t, b, s, logical.ReadOperation, path, nil, true)
	}
	if len(f.accounts) != 0 {
		t.Fatal("Denied requests created accounts")
	}
	for _, ttl := range []int{-1, 0, 59, 901, 86400} {
		testRequest(t, b, s, logical.UpdateOperation, "roles/bad",
			map[string]any{"omni_role": "Operator", "ttl": ttl}, true)
	}
	testRequest(t, b, s, logical.UpdateOperation, "roles/bad",
		map[string]any{"omni_role": "InfraProvider"}, true)
	testRequest(t, b, s, logical.UpdateOperation, "roles/bad",
		map[string]any{"cluster": "talos-default"}, true)
}

func TestConfigurationIsWriteOnlyAndEndpointImmutable(t *testing.T) {
	b, s, _ := testBackend(t)
	response := testRequest(t, b, s, logical.ReadOperation, "config", nil, false)
	if len(response.Data) != 2 || response.Data["configured"] != true {
		t.Fatal("Configuration read exposes unexpected fields")
	}
	var cfg config
	_, _ = load(context.Background(), s, "config", &cfg)
	for _, endpoint := range []string{
		"http://omni.example.invalid", "https://other.example.invalid", "https://user@omni.example.invalid",
		"https://omni.example.invalid?redirect=1", "https://omni.example.invalid/path",
	} {
		testRequest(t, b, s, logical.UpdateOperation, "config",
			map[string]any{"endpoint": endpoint, "service_account_key": cfg.Key}, true)
	}
	testRequest(t, b, s, logical.DeleteOperation, "config", nil, true)
	testRequest(t, b, s, logical.UpdateOperation, "config",
		map[string]any{"endpoint": cfg.Endpoint, "service_account_key": cfg.Key}, false)
}

func TestFailedIssuanceAndCrashRecovery(t *testing.T) {
	b, s, f := testBackend(t)
	f.failCreate, f.failDestroy = true, true
	testRequest(t, b, s, logical.UpdateOperation, "creds/operator", nil, true)
	names, _ := s.List(context.Background(), "accounts/")
	if len(names) != 1 || len(f.accounts) != 1 {
		t.Fatal("Ambiguous creation lost cleanup metadata")
	}
	// A fresh backend instance simulates a plugin restart.
	restarted := newBackend()
	restarted.connect = b.connect
	f.failDestroy = false
	if restarted.cleanupExpired(context.Background(), &logical.Request{Storage: s}) != nil || len(f.accounts) != 0 {
		t.Fatal("Restart did not clean the failed issuance")
	}
	f.failCreate = false
	response := testRequest(t, b, s, logical.UpdateOperation, "creds/operator", nil, false)
	b.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	if b.cleanupExpired(context.Background(), &logical.Request{Storage: s}) != nil || len(f.accounts) != 0 {
		t.Fatal("Orphaned expired account was not cleaned")
	}
	if response.Secret.Renewable {
		t.Fatal("Cryptographically fixed key is renewable")
	}
}

func TestRevocationRetriesAfterUpstreamFailure(t *testing.T) {
	b, s, f := testBackend(t)
	response := testRequest(t, b, s, logical.UpdateOperation, "creds/operator", nil, false)
	req := &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: response.Secret}
	f.failDestroy = true
	if _, err := b.HandleRequest(context.Background(), req); err == nil {
		t.Fatal("Revocation failure was silently accepted")
	}
	names, _ := s.List(context.Background(), "accounts/")
	if len(names) != 1 {
		t.Fatal("Failed revocation lost its retry record")
	}
	f.failDestroy = false
	if _, err := b.HandleRequest(context.Background(), req); err != nil || len(f.accounts) != 0 {
		t.Fatal("Revocation retry did not clean the account")
	}
}

func TestKubernetesScopeLifetimeAndRevocationWarning(t *testing.T) {
	b, s, f := testBackend(t)
	response := testRequest(t, b, s, logical.UpdateOperation, "kubeconfig/operator", nil, false)
	if response.Secret == nil || response.Secret.Renewable || len(response.Warnings) == 0 ||
		f.lastUser != "openbao:"+testEntity || f.kubernetesTTL != maxTTL || len(f.lastGroups) != 1 ||
		f.lastGroups[0] != "openbao:operators" {
		t.Fatal("Kubernetes issuance did not preserve role and entity constraints")
	}
	var r role
	_, _ = load(context.Background(), s, "roles/operator", &r)
	now := time.Now().UTC().Truncate(time.Second)
	for _, data := range [][]byte{
		testKubeconfig(r.Cluster, "someone-else", r.Groups, now.Add(maxTTL)),
		testKubeconfig("other-cluster", f.lastUser, r.Groups, now.Add(maxTTL)),
		testKubeconfig(r.Cluster, f.lastUser, []string{"system:masters"}, now.Add(maxTTL)),
		testKubeconfig(r.Cluster, f.lastUser, r.Groups, now.Add(time.Hour)),
		testKubeconfig(r.Cluster, f.lastUser, r.Groups, now.Add(-time.Minute)),
	} {
		if _, _, err := parseKubeconfig(data, r, f.lastUser, now, maxTTL); err == nil {
			t.Fatal("Invalid upstream scope or expiration was accepted")
		}
	}
}

func TestConcurrentIssuanceAndRevocation(t *testing.T) {
	b, s, f := testBackend(t)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			response, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation, Path: "creds/operator", Storage: s, EntityID: testEntity,
			})
			if err != nil || response == nil || response.IsError() {
				t.Error("Concurrent issuance failed")
				return
			}
			if _, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.RevokeOperation, Storage: s, Secret: response.Secret,
			}); err != nil {
				t.Error("Concurrent revocation failed")
			}
		})
	}
	wg.Wait()
	if len(f.accounts) != 0 {
		t.Fatal("Concurrent issuance left accounts behind")
	}
}
