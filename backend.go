// Package omni implements leased Omni credentials for OpenBao.
package omni

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	Version = "v0.1.0"
	maxTTL  = 15 * time.Minute
)

var (
	errStorage = errors.New("Omni plugin storage operation failed")
	errRemote  = errors.New("Omni operation failed; upstream diagnostics withheld")
	validName  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
	validID    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type backend struct {
	*framework.Backend
	mu      sync.RWMutex
	connect func(config) (upstream, error)
	now     func() time.Time
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() *backend {
	b := &backend{connect: connectOmni, now: time.Now}
	b.Backend = &framework.Backend{
		Help:        "Issue short-lived Omni PGP keys and Omni Kubernetes proxy tokens.",
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"config"},
		},
		RunningVersion: Version,
	}
	b.Paths = []*framework.Path{b.configPath(), b.rolePath(), b.rolesPath(), b.credsPath(), b.kubeconfigPath()}
	b.Secrets = []*framework.Secret{
		{Type: "omni_key", Revoke: b.revokeKey},
		{Type: "kubernetes_jwt", Revoke: b.revokeJWT},
	}
	b.PeriodicFunc = b.cleanupExpired
	return b
}

func validEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		u.Opaque == "" && (u.Path == "" || u.Path == "/")
}

func save(ctx context.Context, s logical.Storage, path string, value any) error {
	entry, err := logical.StorageEntryJSON(path, value)
	if err != nil || s.Put(ctx, entry) != nil {
		return errStorage
	}
	return nil
}

func load(ctx context.Context, s logical.Storage, path string, value any) (bool, error) {
	entry, err := s.Get(ctx, path)
	if err != nil {
		return false, errStorage
	}
	if entry == nil {
		return false, nil
	}
	if entry.DecodeJSON(value) != nil {
		return false, errStorage
	}
	return true, nil
}

func remove(ctx context.Context, s logical.Storage, path string) error {
	if s.Delete(ctx, path) != nil {
		return errStorage
	}
	return nil
}
