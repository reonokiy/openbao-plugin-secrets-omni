package omni

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type role struct {
	OmniRole string   `json:"omni_role"`
	Cluster  string   `json:"cluster"`
	Groups   []string `json:"groups"`
	TTL      int      `json:"ttl"`
}

func (b *backend) rolePath() *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name":      {Type: framework.TypeString},
			"omni_role": {Type: framework.TypeString},
			"cluster":   {Type: framework.TypeString},
			"groups":    {Type: framework.TypeCommaStringSlice},
			"ttl":       {Type: framework.TypeDurationSecond, Default: 900},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.writeRole,
			logical.ReadOperation:   b.readRole,
			logical.DeleteOperation: b.deleteRole,
		},
		HelpSynopsis: "Pin permissions and a 60-900 second lifetime; empty fields disable each credential type.",
	}
}

func (b *backend) rolesPath() *framework.Path {
	return &framework.Path{
		Pattern: "roles/?",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
				names, err := req.Storage.List(ctx, "roles/")
				if err != nil {
					return nil, errStorage
				}
				return logical.ListResponse(names), nil
			},
		},
		HelpSynopsis: "List configured issuance roles.",
	}
}

func (b *backend) writeRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if !validName.MatchString(name) {
		return logical.ErrorResponse("Invalid role name"), nil
	}
	for field := range req.Data {
		if !slices.Contains([]string{"name", "omni_role", "cluster", "groups", "ttl"}, field) {
			return logical.ErrorResponse("Unsupported role field"), nil
		}
	}
	r := role{
		OmniRole: d.Get("omni_role").(string), Cluster: d.Get("cluster").(string),
		Groups: d.Get("groups").([]string), TTL: d.Get("ttl").(int),
	}
	if r.TTL < 60 || time.Duration(r.TTL)*time.Second > maxTTL {
		return logical.ErrorResponse("TTL must be between 60 and 900 seconds"), nil
	}
	if r.OmniRole != "" && !slices.Contains([]string{"Reader", "Auditor", "Operator", "Admin"}, r.OmniRole) {
		return logical.ErrorResponse("Unsupported Omni role"), nil
	}
	if (r.Cluster == "") != (len(r.Groups) == 0) || (r.Cluster != "" && !validName.MatchString(r.Cluster)) {
		return logical.ErrorResponse("Kubernetes issuance requires a valid fixed cluster and groups"), nil
	}
	for _, group := range r.Groups {
		if strings.TrimSpace(group) != group || group == "" || len(group) > 128 || strings.ContainsAny(group, "\r\n\x00") {
			return logical.ErrorResponse("Invalid Kubernetes group"), nil
		}
	}
	if r.OmniRole == "" && r.Cluster == "" {
		return logical.ErrorResponse("Enable at least one credential type"), nil
	}
	if err := save(ctx, req.Storage, "roles/"+name, r); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) readRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var r role
	ok, err := load(ctx, req.Storage, "roles/"+d.Get("name").(string), &r)
	if err != nil || !ok {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"omni_role": r.OmniRole, "cluster": r.Cluster, "groups": r.Groups, "ttl": r.TTL,
	}}, nil
}

func (b *backend) deleteRole(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, remove(ctx, req.Storage, "roles/"+d.Get("name").(string))
}
