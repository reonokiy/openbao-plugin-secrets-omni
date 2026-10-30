# Development

This repository contains the generic OpenBao Omni secrets engine and its public
OCI image. Cluster deployment, operator policy and CLI session integration
belong in their consuming infrastructure repository.

Pin dependencies and tool versions. Keep the distribution image to the static
executable at `/openbao-plugin-secrets-omni`; OpenBao extracts it without running
the container. Never add operator credentials or environment-specific
configuration to the image.

Never retrieve, display, decode or persist real credentials, credential caches,
Kubernetes Secret values or Terraform state. Do not contact production services
to test this plugin. Test credentials must be generated in memory, and local
OpenBao output containing test tokens must be consumed and discarded.

The issuer key is write-only and seal-wrapped. Its endpoint is immutable.
Preserve entity-bound identities, a 15-minute maximum, nonrenewable leases,
durable cleanup metadata before upstream creation, and retryable revocation.
Omni Kubernetes JWTs have no individual revocation API; document that they
remain usable until native expiry and existing streams can last longer.

Run `mise run test` and `mise run integration` after lifecycle changes.
Publishing a release requires clean reviewed sources. Consumer deployments
must pin both the OCI image digest and the binary checksum.
