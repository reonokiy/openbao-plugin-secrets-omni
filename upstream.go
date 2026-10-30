package omni

import (
	"context"
	"time"

	"github.com/siderolabs/omni/client/pkg/client"
	"github.com/siderolabs/omni/client/pkg/client/management"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type upstream interface {
	create(context.Context, string, string, string) error
	destroy(context.Context, string) error
	kubeconfig(context.Context, string, string, []string, time.Duration) ([]byte, error)
	close()
}

type omniClient struct{ client *client.Client }

func connectOmni(cfg config) (upstream, error) {
	c, err := client.New(cfg.Endpoint, client.WithServiceAccount(cfg.Key))
	if err != nil {
		return nil, errRemote
	}
	return &omniClient{client: c}, nil
}

func (c *omniClient) create(ctx context.Context, name, publicKey, role string) error {
	_, err := c.client.Management().CreateServiceAccount(ctx, name, publicKey, role, false)
	if err != nil {
		return errRemote
	}
	return nil
}

func (c *omniClient) destroy(ctx context.Context, name string) error {
	err := c.client.Management().DestroyServiceAccount(ctx, name)
	if err != nil && status.Code(err) != codes.NotFound {
		return errRemote
	}
	return nil
}

func (c *omniClient) kubeconfig(ctx context.Context, cluster, user string, groups []string, ttl time.Duration) ([]byte, error) {
	data, err := c.client.Management().WithCluster(cluster).Kubeconfig(ctx, management.WithServiceAccount(ttl, user, groups...))
	if err != nil {
		return nil, errRemote
	}
	return data, nil
}

func (c *omniClient) close() { _ = c.client.Close() }
