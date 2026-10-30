package omni

import (
	"context"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/siderolabs/go-api-signature/pkg/serviceaccount"
)

type config struct {
	Endpoint string `json:"endpoint"`
	Key      string `json:"service_account_key"`
}

func (b *backend) configPath() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"endpoint":            {Type: framework.TypeString, Required: true},
			"service_account_key": {Type: framework.TypeString, Required: true, DisplayAttrs: &framework.DisplayAttributes{Sensitive: true}},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.writeConfig,
			logical.ReadOperation:   b.readConfig,
		},
		HelpSynopsis: "Configure a verified HTTPS Omni endpoint and write-only administrator key.",
	}
}

func (b *backend) writeConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for field := range req.Data {
		if field != "endpoint" && field != "service_account_key" {
			return logical.ErrorResponse("Unsupported configuration field"), nil
		}
	}
	cfg := config{Endpoint: strings.TrimSuffix(d.Get("endpoint").(string), "/"), Key: d.Get("service_account_key").(string)}
	if !validEndpoint(cfg.Endpoint) || cfg.Key == "" {
		return logical.ErrorResponse("A verified HTTPS endpoint and service account key are required"), nil
	}
	decoded, err := serviceaccount.Decode(cfg.Key)
	if err != nil || decoded.Key.IsExpired(0) || strings.HasPrefix(decoded.Name, "bao-") {
		return logical.ErrorResponse("A valid, independent Omni administrator service account key is required"), nil
	}
	var previous config
	ok, err := load(ctx, req.Storage, "config", &previous)
	if err != nil {
		return nil, err
	}
	// Never direct an existing lease's cleanup to another Omni account.
	if ok && previous.Endpoint != cfg.Endpoint {
		return logical.ErrorResponse("Endpoint is immutable; use a separate mount for another Omni account"), nil
	}
	if err := save(ctx, req.Storage, "config", cfg); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) readConfig(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var cfg config
	ok, err := load(ctx, req.Storage, "config", &cfg)
	if err != nil || !ok {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"endpoint": cfg.Endpoint, "configured": cfg.Key != "",
	}}, nil
}
