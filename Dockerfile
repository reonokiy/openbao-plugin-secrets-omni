FROM scratch
COPY openbao-plugin-secrets-omni /openbao-plugin-secrets-omni
ENTRYPOINT ["/openbao-plugin-secrets-omni"]
LABEL org.opencontainers.image.source="https://github.com/reonokiy/openbao-plugin-secrets-omni" \
      org.opencontainers.image.description="Static OpenBao Omni secrets plugin for verified OCI distribution"
