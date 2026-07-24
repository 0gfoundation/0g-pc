# Phala Cloud deployment (cloud-TEE gateway)

Deploys the [`gateway`](../../client/cmd/gateway) to [Phala Cloud](https://phala.com)
via [dstack](https://docs.phala.com). This is the server-run, 0G-operated,
cloud-TEE form of the client core — see [`docs/design/cloud-gateway.md`](../../docs/design/cloud-gateway.md)
for the trust model (tier 2.5: confidential by default, cheating publicly
detectable).

## How it works

- The gateway serves **plaintext HTTP** on `:8443`. TLS is terminated by
  dstack's **ZT-HTTPS** front end *inside the enclave* — the private key is
  derived by dstack-kms and never leaves the TEE — so the container itself does
  no TLS.
- dstack's `tproxy` gateway exposes container ports at a public HTTPS URL using
  the ingress pattern:

  | Ingress hostname | Maps to CVM port |
  |------------------|------------------|
  | `<app-id>.<base_domain>` | 80 / 443 |
  | `<app-id>-8443.<base_domain>` | **8443** (this deployment) |
  | `<app-id>-8443s.<base_domain>` | 8443 with TLS passthrough (app terminates TLS — not used here) |

  So once deployed the gateway is reachable at
  `https://<app-id>-8443.<base_domain>` — point an OpenAI-compatible client's
  `base_url` there, e.g. health check: `curl https://<app-id>-8443.<base_domain>/healthz`.

## Deploy

Reference [`docker-compose.yml`](./docker-compose.yml) from the Phala Cloud
dashboard, or via the CLI:

```sh
phala cvm create --compose deploy/phala/docker-compose.yml
```

## Pin the image digest

In a TEE the compose file is **measured** into the CVM's attestation, so a
floating `:latest` tag makes the measurement change unpredictably. For a
reproducible, verifiable deployment, pin the image to an immutable digest:

```yaml
image: ghcr.io/0gfoundation/0g-pc-e2ee-gateway@sha256:<digest>
```

Get the digest for a tag with:

```sh
docker buildx imagetools inspect ghcr.io/0gfoundation/0g-pc-e2ee-gateway:latest
```

## Notes

- **No secrets or volumes.** The gateway holds no pinned provider key: it routes
  per request and derives each provider's enc key + signer from the broker. It
  defaults to the 0G router; override with `--router-url` in the compose
  `command`.
- Attestation (`/quote`) is a stub until issue #19 lands; `/healthz` is live.
