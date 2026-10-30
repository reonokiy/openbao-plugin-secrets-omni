# OpenBao Omni secrets engine

This Go plugin issues short-lived credentials through the Omni v1.12.2
management API. It uses OpenBao SDK v2.7.1 and registers as `secret/omni`
v0.1.0. Dependencies, including Omni's upstream YAML replacement, are locked
in `go.mod` and `go.sum`.

Source, tests, releases and the OCI image are maintained in this repository.
The image is `ghcr.io/reonokiy/openbao-plugin-secrets-omni`. Cluster-specific
OpenBao policies, Kubernetes RBAC and CLI session helpers belong to the
consuming infrastructure repository.

## API

| Path | Operation | Behavior |
| --- | --- | --- |
| `config` | write | Verified HTTPS endpoint and write-only `service_account_key` |
| `config` | read | Endpoint and configured flag only |
| `roles/:name` | write/read/delete | Fixed `omni_role`, `cluster`, `groups`, `ttl` |
| `roles` | list | Role names |
| `creds/:role` | write | Leased encoded PGP key and independent temporary account |
| `kubeconfig/:role` | write | Leased JWT, server, public CA, cluster and expiry |

Both issuance endpoints require an authenticated identity entity. They reject
caller-supplied TTL, identity, permissions, groups, cluster or endpoint.
Role TTL is 60-900 seconds. Neither credential type is renewable.

The issuer's endpoint cannot change on an existing mount. Key rotation on the
same endpoint is supported. There is no configuration delete endpoint, so
ordinary rotation cannot discard authorization needed to clean outstanding
accounts.

Each PGP issuance creates one uniquely named `bao-<entity>-<random>` account.
Only cleanup metadata is persisted before the remote create call; private
keys appear only in the issuance response. Lease revocation deletes the
upstream account. OpenBao periodic rollback also retries failed/expired
account cleanup after plugin restarts, including creation failures whose
remote outcome is ambiguous. Upstream and storage errors are sanitized.
Native PGP expiry provides a separate limit during connectivity outages.
Deletion can affect subsequent API calls; it does not terminate existing
streams or undo completed operations.

Omni JWTs have no individual revocation API in this version. Their lease
revoke callback cannot invalidate the JWT. They stop working at their embedded
expiry for new authentication; existing connections can last longer. Every
issuance returns this limitation as a warning. Revoking the parent OpenBao
token prevents further issuance and revokes its leased PGP accounts.

The plugin needs an independent, dedicated Omni Admin service account to
create/delete temporary accounts. Temporary accounts use explicit roles and
never inherit the issuer's Admin role. The default operator is `Operator`,
not `Admin`; read-only is `Reader`. Omni roles are account-wide and do not
constrain omnictl to the Kubernetes cluster configured on the same role.
These are trusted operator credentials: an Operator can call Omni's own
Kubernetes-token API, and an Admin can create other credentials. Short-lived
issuance is not a sandbox against a malicious privileged operator.

## Build and verification

```sh
mise install --locked
mise run lint
mise run test
mise run integration
```

The integration task builds the actual external executable, starts the pinned
local OpenBao CLI in dev mode, and connects the plugin to an isolated TLS
gRPC management server. It checks plugin registration, entity-bound signing
keys, Kubernetes credentials, ACL denials, explicit lease revocation and parent
token revocation. Test credentials are generated in memory; server output is
consumed and discarded. Only binaries, public CA and non-secret configuration
are written to disk. No production services are contacted.

The fake Omni server exercises the client API and plugin protocol, not Omni's
production authorization enforcement or real Kubernetes access. Production
acceptance must separately verify native key expiry, permission boundaries,
Kubernetes RBAC and actual account deletion without displaying credentials.

`mise run build` creates `dist/` with the Linux amd64
binary, checksum, source metadata, plugin HCL and a Docker build context. The
binary is static and built with `-trimpath` and `-buildvcs=false`. The OCI image
contains only the executable at its root. OpenBao's existing OCI downloader
extracts and verifies it in the per-Pod plugin directory. Preserve
`plugin_download_behavior = "warn"` so a plugin registry outage does not prevent
the core OpenBao server from starting.

## Releases and OCI installation

The `Release` workflow verifies a version tag with the full test and integration
suite, then publishes a dedicated GHCR image and GitHub release assets:

- Static Linux amd64 executable.
- `manifest.json` with binary SHA256, source revision and compatibility.
- `SHA256SUMS` and manual registration `plugin.hcl`.
- `image.txt` with the immutable OCI image reference.

The version tag must equal the plugin version and builds require clean source.
On first publication, make the dedicated GHCR package public in its package
settings and verify anonymous pulls before enabling it in a consumer.
Repository visibility and package visibility are separate settings.

Consumers should download the release metadata, review its revision/checksum,
and pin both the image digest from `image.txt` and binary SHA256 from
`manifest.json`:

```hcl
plugin "secret" "omni" {
  image = "ghcr.io/reonokiy/openbao-plugin-secrets-omni@sha256:<image-digest>"
  version = "v0.1.0"
  binary_name = "openbao-plugin-secrets-omni"
  sha256sum = "<binary-sha256>"
}
```

Enable OpenBao's OCI download and automatic registration in its configuration.
Use a writable per-server plugin directory. Preserve the deployment's chosen
download failure policy and independent recovery authentication.
The example placeholders must be replaced with verified release values.
This plugin's build and release workflows never modify consumers or contact
production OpenBao, Omni or Kubernetes services.
