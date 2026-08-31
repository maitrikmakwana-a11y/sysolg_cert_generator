# QA Certificate Factory - Status

## Overview
This project is a self-hosted certificate management platform for QA and testing environments. The goal is to generate isolated root CAs, issue signed leaf certificates, support TLS and mTLS workflows, and export trust material for downstream systems such as rsyslog, apps, and test clients.

---

## Completed

### Phase 0 - Project setup
- Backend created with Python + FastAPI
- Frontend created with React + Vite + TypeScript
- Project structure initialized for local development
- Dependencies installed and validated

### Phase 1 - Core certificate generation
- Root CA generation per environment
- Leaf certificate issuance for test domains
- Built-in certificate templates
- SQLite-backed persistence for CA and certificate records
- REST API endpoints for automation
- Trust script generation for OS trust installation
- Bundle merge support for multiple PEM CAs
- Download/export actions for generated artifacts

### Export and download support
- Download generated certificate
- Download generated private key
- Download CA certificate
- Download CA private key
- Download trust script
- Merge and download trusted CA bundle

### Verified working flows
- Backend health endpoint is responding
- CA creation API works
- Certificate generation API works
- Frontend build succeeds
- Runtime verification completed for the main certificate lifecycle

---

## What is done in the current app
- CA and certificate creation flow is functional
- UI can generate certs for a selected CA and template
- Bundle merge is available for combining trusted certs
- Download options are available for major generated outputs
- The app is ready for additional Phase 2 feature expansion

---

## To be done next

### Phase 2 - TLS / mTLS and trust bundle management
- Explicit TLS and mTLS mode selection on certificate issuance
- External root CA and client certificate import flow with PEM validation
- Separate persistence for imported trust materials
- Combined trust bundle generation from internal CAs, imported roots, and PEM chains
- Client certificates are stored separately and cannot be added to root trust bundles
- API and UI controls for selecting bundle sources and downloading the result

### Phase 3 - Certificate and environment management
- Comprehensive certificate and CA inventory view
- Certificate metadata including serial, issuer, SANs, validity, and status
- Inventory filtering by status and environment through the API
- CA rename and lifecycle status controls
- Certificate revoke/expire/reactivate controls
- Environment association shown in the inventory dashboard

### Phase 4 - Advanced exports and automation
- Export all generated artifacts as a single ZIP package
- Export certificate metadata in JSON/CSV
- Add automation API for repeated cert issuance
- Add config snippets for nginx, Apache, OpenSSL, rsyslog, and mTLS clients

### Phase 5 - Security and production readiness
- Configurable API-key authentication via `CERT_FACTORY_API_KEY`
- Separate admin/read-only API keys with write protection
- Audit logging for every HTTP request with a protected audit endpoint
- Private keys removed from normal CA/certificate listing responses
- Optional Fernet encryption of private keys at rest with existing-record migration
- Strict naming, environment, and domain validation
- Uploaded PEM bundle and certificate type validation
- Safe artifact filename normalization for exports
- Fine-grained user/role administration remains future hardening work

### Stateless syslog workflow
- One-click complete syslog ZIP package with certificates, trust bundle, rsyslog configuration, and setup instructions
- mTLS package supports existing AP client certificates without generating unnecessary client CA material

---

## Recommended next milestone
Focus on completing the full mTLS and combined trust bundle workflow:
1. Upload external CA / APs CA
2. Store internal CA and imported CA separately
3. Merge both into a final trust bundle
4. Generate certs against the selected trust chain
5. Download the completed bundle and install script

This will complete the transition from a certificate generator to a QA-ready TLS/mTLS trust management platform.
