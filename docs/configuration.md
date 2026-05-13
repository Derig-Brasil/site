# Configuration Guide

The DÉRIG website uses Cloudflare KV for centralized, non-secret configuration management.

## Centralized Configuration (KV)

The Worker loads a JSON config blob from the `CONFIG` KV binding at key `config` and hydrates missing values at runtime.

### Resolution Order
1. **ENV/Vars/Secrets**: Overrides everything else.
2. **KV stored config**: Primary source for non-secret config.
3. **Code defaults**: Fallback if nothing else is defined.

> [!IMPORTANT]
> **Secrets must NOT go into KV.** Keep these as Cloudflare secrets:
> - `MC_API_KEY`
> - `DKIM_PRIVATE_KEY`
> - `JWT_SECRET`

### Supported KV Keys
The following non-secret keys are currently supported from KV:
- `ALLOW_ORIGIN`
- `DKIM_DOMAIN`
- `DKIM_SELECTOR`
- `EMAIL_CONTACT`
- `EMAIL_REGISTRATION`
- `EMAIL_WORKWITHUS`
- `FROM_EMAIL`

## Setup KV Namespaces

Create the namespaces (one per environment):

```bash
wrangler kv namespace create site-config
wrangler kv namespace create site-config --env test
```

Copy the resulting Namespace IDs into `wrangler.jsonc` under `kv_namespaces` for the default (prod) and `env.test` sections, replacing the placeholders `REPLACE_WITH_PROD_KV_ID` and `REPLACE_WITH_TEST_KV_ID`.

## Seed or Update Config

The Worker expects a single JSON object stored at key `config`:

```bash
# Example production configuration
wrangler kv:key put --binding CONFIG config '{
  "ALLOW_ORIGIN": "https://derig.com.br",
  ...
}'

# Example test configuration
wrangler kv:key put --env test --binding CONFIG config '{
  "ALLOW_ORIGIN": "*",
  ...
}'
```

Updating the config uses the same command; it overwrites the existing value.

## Environment Overrides

Any variable provided via Cloudflare Env Vars or Secrets will override the KV value at runtime. You can set overrides via the Cloudflare dashboard or Wrangler:

```bash
# Vars (non-secret)
wrangler deploy -v ALLOW_ORIGIN=*

# Secrets (interactive prompts)
wrangler secret put MC_API_KEY
wrangler secret put DKIM_PRIVATE_KEY
wrangler secret put JWT_SECRET
```

These overrides apply independently for the `test` environment when using the `--env test` flag.
