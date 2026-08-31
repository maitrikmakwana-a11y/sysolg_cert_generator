# QA Certificate Factory

A self-hosted certificate management tool for QA and test environments.

## Features
- Generate isolated root CAs per environment
- Create signed leaf certificates for QA testing
- Use built-in certificate templates
- Download trust scripts for local machine trust installation
- Combine CA PEM files into a trusted bundle for TLS/mTLS scenarios
- Import external root CAs and client certificates for TLS/mTLS test environments
- Expose a REST API for automation

## Run locally

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

For deployments, set `CERT_FACTORY_API_KEY` on the backend and `VITE_API_KEY`
on the frontend build. The backend then requires that value in `X-API-Key` for
every API request. If unset, local development remains unauthenticated.

For stronger separation, set `CERT_FACTORY_ADMIN_API_KEY` and
`CERT_FACTORY_READONLY_API_KEY`; the latter can only read resources. Set
`CERT_FACTORY_ENCRYPTION_KEY` to a generated Fernet key to encrypt existing and
new private keys in SQLite. Keep this key outside the database and back it up
securely.

### Docker Compose

```bash
docker-compose up --build
```

## Main API endpoints

- GET /health
- GET /api/v1/templates
- POST /api/v1/ca
- GET /api/v1/ca
- POST /api/v1/certificates/generate
- POST /api/v1/trust-materials/import
- GET /api/v1/trust-materials
- GET /api/v1/certificates
- GET /api/v1/inventory
- PATCH /api/v1/ca/{ca_id}
- PATCH /api/v1/certificates/{certificate_id}
- GET /api/v1/exports/inventory?format=json|csv
- GET /api/v1/exports/package
- GET /api/v1/config-snippets/{certificate_id}
- GET /api/v1/audit
- POST /api/v1/syslog/package
- POST /api/v1/bundles/merge
- GET /api/v1/bundles
- POST /api/v1/trust-script

`/api/v1/bundles/merge` accepts `ca_ids`, `external_material_ids` (root CAs only),
and/or the existing `ca_pems` list. Certificate issuance accepts `mode: "tls"`
or `mode: "mtls"`; mTLS uses the `mtls_client_auth` template.
