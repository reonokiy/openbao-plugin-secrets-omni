package main

import (
	"flag"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"

	omni "github.com/reonokiy/openbao-plugin-secrets-omni"
)

func main() {
	meta := new(api.PluginAPIClientMeta)
	flags := meta.FlagSet()
	flags.Parse(os.Args[1:])
	tlsConfig := meta.GetTLSConfig()
	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: omni.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(tlsConfig),
		Logger:             hclog.NewNullLogger(),
	}); err != nil {
		// Upstream errors may contain credentials or signed request details.
		flag.CommandLine.Output().Write([]byte("Omni secrets plugin failed; diagnostics withheld\n"))
		os.Exit(1)
	}
}
