package omni

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/siderolabs/go-api-signature/pkg/pgp"
	"github.com/siderolabs/go-api-signature/pkg/serviceaccount"
	management "github.com/siderolabs/omni/client/api/omni/management"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

type testManagement struct {
	management.UnimplementedManagementServiceServer
	mu       sync.Mutex
	accounts map[string]bool
}

func (m *testManagement) CreateServiceAccount(_ context.Context, req *management.CreateServiceAccountRequest) (*management.CreateServiceAccountResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accounts[req.Name] = true
	return &management.CreateServiceAccountResponse{}, nil
}

func (m *testManagement) DestroyServiceAccount(_ context.Context, req *management.DestroyServiceAccountRequest) (*emptypb.Empty, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.accounts, req.Name)
	return &emptypb.Empty{}, nil
}

func (m *testManagement) Kubeconfig(ctx context.Context, req *management.KubeconfigRequest) (*management.KubeconfigResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	return &management.KubeconfigResponse{Kubeconfig: testKubeconfig(
		md.Get("context")[0], req.ServiceAccountUser, req.ServiceAccountGroups, time.Now().Add(req.ServiceAccountTtl.AsDuration()),
	)}, nil
}

func (m *testManagement) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.accounts)
}

func TestPluginInOpenBao(t *testing.T) {
	pluginBinary := os.Getenv("OPENBAO_OMNI_PLUGIN")
	if pluginBinary == "" {
		t.Skip("Set OPENBAO_OMNI_PLUGIN to run the actual OpenBao/plugin integration test")
	}
	bao, err := exec.LookPath("bao")
	if err != nil {
		t.Fatal("Pinned OpenBao executable unavailable")
	}
	directory := t.TempDir()
	// Only a public CA certificate is written. TLS and PGP private keys, dev
	// root token and user tokens remain exclusively in process memory.
	certificateServer := httptest.NewTLSServer(nil)
	cert := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	caFile := filepath.Join(directory, "ca.pem")
	if os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600) != nil {
		t.Fatal("Public test CA write failed")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("Test Omni listener failed")
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	})))
	remote := &testManagement{accounts: map[string]bool{}}
	management.RegisterManagementServiceServer(server, remote)
	go server.Serve(listener)
	defer server.Stop()
	endpoint := "https://" + listener.Addr().String()
	pluginName := "openbao-plugin-secrets-omni"
	pluginDir := filepath.Join(directory, "plugins")
	if os.Mkdir(pluginDir, 0700) != nil {
		t.Fatal("Test plugin directory setup failed")
	}
	binary, err := os.ReadFile(pluginBinary)
	if err != nil {
		t.Fatal("Plugin checksum read failed")
	}
	if os.WriteFile(filepath.Join(pluginDir, pluginName), binary, 0700) != nil {
		t.Fatal("Test plugin provisioning failed")
	}
	sum := sha256.Sum256(binary)
	configFile := filepath.Join(directory, "config.hcl")
	if os.WriteFile(configFile, []byte("disable_mlock = true\nplugin_directory = \""+pluginDir+"\"\n"), 0600) != nil {
		t.Fatal("Test OpenBao configuration write failed")
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("Test OpenBao port allocation failed")
	}
	address := reservation.Addr().String()
	reservation.Close()
	cmd := exec.Command(bao, "server", "-dev", "-dev-no-store-token",
		"-dev-listen-address="+address, "-config="+configFile)
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+caFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal("Test server output pipe failed")
	}
	cmd.Stderr = cmd.Stdout
	if cmd.Start() != nil {
		t.Fatal("Isolated OpenBao startup failed")
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	root := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if _, token, found := strings.Cut(line, "Root Token: "); found {
				select {
				case root <- strings.TrimSpace(token):
				default:
				}
			}
			// All startup/plugin output is discarded, including credentials.
		}
	}()
	var rootToken string
	select {
	case rootToken = <-root:
	case <-time.After(20 * time.Second):
		t.Fatal("Isolated OpenBao startup timed out; diagnostics suppressed")
	}
	client, err := api.NewClient(&api.Config{Address: "http://" + address})
	if err != nil {
		t.Fatal("Test API client setup failed")
	}
	client.SetToken(rootToken)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	write := func(c *api.Client, path string, data map[string]any) *api.Secret {
		t.Helper()
		result, err := c.Logical().WriteWithContext(ctx, path, data)
		if err != nil {
			statusCode := 0
			var categories []string
			if response, ok := err.(*api.ResponseError); ok {
				statusCode = response.StatusCode
				for _, category := range []string{"permission", "symlink", "checksum", "mlock", "executable", "version", "not found", "transport", "handshake", "missing"} {
					if strings.Contains(strings.ToLower(strings.Join(response.Errors, " ")), category) {
						categories = append(categories, category)
					}
				}
			}
			t.Fatalf("Isolated API write failed: %s; HTTP %d; categories %v; diagnostics suppressed", path, statusCode, categories)
		}
		return result
	}
	write(client, "sys/plugins/catalog/secret/omni", map[string]any{
		"command": pluginName, "sha256": hex.EncodeToString(sum[:]), "version": Version,
	})
	write(client, "sys/mounts/omni", map[string]any{"type": "omni", "plugin_version": Version})
	key, err := pgp.GenerateKey("integration-issuer", "isolated test", "integration-issuer@serviceaccount.omni.sidero.dev", time.Hour)
	if err != nil {
		t.Fatal("Test issuer generation failed")
	}
	encoded, err := serviceaccount.Encode("integration-issuer", key)
	if err != nil {
		t.Fatal("Test issuer encoding failed")
	}
	write(client, "omni/config", map[string]any{"endpoint": endpoint, "service_account_key": encoded})
	write(client, "omni/roles/operator", map[string]any{
		"omni_role": "Operator", "cluster": "talos-default", "groups": []string{"openbao:operators"}, "ttl": 60,
	})
	write(client, "sys/policies/acl/test-omni", map[string]any{"policy": `
path "omni/creds/operator" { capabilities = ["update"] }
path "omni/kubeconfig/operator" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
`})
	write(client, "sys/auth/test-users", map[string]any{"type": "userpass"})
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	password := hex.EncodeToString(random)
	write(client, "auth/test-users/users/alice", map[string]any{
		"password": password, "policies": []string{"test-omni"}, "token_no_default_policy": true,
	})
	login := write(client, "auth/test-users/login/alice", map[string]any{"password": password})
	user, _ := client.Clone()
	user.SetToken(login.Auth.ClientToken)
	lease := write(user, "omni/creds/operator", nil)
	if lease.LeaseID == "" || lease.Renewable || lease.LeaseDuration > 60 || remote.count() != 1 {
		t.Fatal("Real plugin key lease is invalid")
	}
	sa, err := serviceaccount.Decode(lease.Data["service_account_key"].(string))
	if err != nil || !strings.HasPrefix(sa.Name, "bao-"+login.Auth.EntityID+"-") {
		t.Fatal("Real plugin key is not entity-bound")
	}
	write(client, "sys/leases/revoke", map[string]any{"lease_id": lease.LeaseID})
	if remote.count() != 0 {
		t.Fatal("OpenBao lease revocation did not delete the upstream account")
	}
	jwt := write(user, "omni/kubeconfig/operator", nil)
	if jwt.Renewable || jwt.LeaseDuration > 60 || len(jwt.Warnings) == 0 {
		t.Fatal("Real plugin Kubernetes lease or warning is invalid")
	}
	if _, err := user.Logical().WriteWithContext(ctx, "omni/config", map[string]any{"endpoint": endpoint}); err == nil {
		t.Fatal("Issuance-only identity modified the manager configuration")
	}
	if _, err := user.Logical().WriteWithContext(ctx, "omni/creds/operator", map[string]any{"ttl": "1h"}); err == nil {
		t.Fatal("Issuance-only identity overrode its TTL")
	}
	write(user, "omni/creds/operator", nil)
	write(user, "auth/token/revoke-self", nil)
	deadline := time.Now().Add(5 * time.Second)
	for remote.count() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if remote.count() != 0 {
		t.Fatal("Parent token revocation left a leased Omni account")
	}
}
