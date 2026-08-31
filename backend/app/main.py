import csv
import datetime
import io
import json
import re
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from .config import API_PREFIX
from .db import (get_trust_material, list_audit_events, list_bundles, list_bundles_with_pem, list_cas, list_certificates, list_trust_materials,
                 save_audit_event, save_bundle, save_ca, save_certificate, save_trust_material, update_ca, update_certificate_status)
from .schemas import (BundleMergeRequest, CACreateRequest, CertificateGenerateRequest,
                      CertificateVerifyRequest, LifecycleUpdateRequest, SyslogConfigRequest, SyslogPackageRequest, TrustMaterialImportRequest, TrustScriptRequest)
from .services.certificate_service import (bundle_ca_pem_files, generate_ca, generate_leaf_certificate,
                                           certificate_metadata, list_available_templates, validate_trust_material)
from .services.trust_script_service import generate_trust_script
from .security import is_read_only_key, require_api_key

app = FastAPI(title="QA Certificate Factory", version="0.1.0", dependencies=[Depends(require_api_key)])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def audit_requests(request: Request, call_next):
    if is_read_only_key(request.headers.get("x-api-key")) and request.method not in {"GET", "HEAD", "OPTIONS"}:
        response = Response(content='{"detail":"Read-only API key cannot modify resources"}', status_code=403, media_type="application/json")
        save_audit_event(request.method, request.url.path, response.status_code)
        return response
    response = await call_next(request)
    save_audit_event(request.method, request.url.path, response.status_code)
    return response


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get(f"{API_PREFIX}/templates")
def list_templates():
    return {"templates": list_available_templates()}


@app.get(f"{API_PREFIX}/ca")
def get_cas():
    return {"cas": [{key: value for key, value in ca.items() if key not in {"cert_pem", "key_pem"}} for ca in list_cas()]}


@app.post(f"{API_PREFIX}/ca")
def create_ca(payload: CACreateRequest):
    cert_pem, key_pem = generate_ca(payload.name, payload.environment)
    # Stateless mode: the browser receives the material and owns the session.
    ca = {"id": 1, "name": payload.name, "environment": payload.environment}
    return {"message": "CA created", "ca": {**ca, "cert_pem": cert_pem, "key_pem": key_pem}}


@app.get(f"{API_PREFIX}/certificates")
def get_certificates():
    return {"certificates": [{key: value for key, value in cert.items() if key not in {"cert_pem", "key_pem"}} for cert in list_certificates()]}


@app.get(f"{API_PREFIX}/audit", dependencies=[Depends(require_api_key)])
def get_audit_log(limit: int = 100):
    return {"events": list_audit_events(min(max(limit, 1), 500))}


@app.get(f"{API_PREFIX}/inventory")
def get_inventory(status: str | None = None, environment: str | None = None):
    cas = list_cas()
    certs = list_certificates()
    if status:
        cas = [item for item in cas if item.get("status") == status]
        certs = [item for item in certs if item.get("status") == status]
    if environment:
        cas = [item for item in cas if item["environment"].lower() == environment.lower()]
        ca_ids = {item["id"] for item in cas}
        certs = [item for item in certs if item["ca_id"] in ca_ids]
    ca_metadata = [{key: value for key, value in item.items() if key not in {"cert_pem", "key_pem"}} for item in cas]
    cert_metadata = []
    for item in certs:
        metadata = certificate_metadata(item["cert_pem"])
        record = {key: value for key, value in item.items() if key not in {"cert_pem", "key_pem"}} | metadata
        if record["status"] == "active" and datetime.datetime.fromisoformat(str(record["not_valid_after"])) < datetime.datetime.now(datetime.timezone.utc):
            record["status"] = "expired"
        cert_metadata.append(record)
    return {"cas": ca_metadata, "certificates": cert_metadata}


@app.get(f"{API_PREFIX}/exports/inventory")
def export_inventory(format: str = "json"):
    inventory = get_inventory()
    if format.lower() == "json":
        return Response(content=json.dumps(inventory, indent=2), media_type="application/json",
                        headers={"Content-Disposition": "attachment; filename=certificate-inventory.json"})
    if format.lower() != "csv":
        raise HTTPException(status_code=400, detail="Format must be json or csv")
    output = io.StringIO()
    fields = ["record_type", "id", "name", "environment", "domain", "template_name", "status", "serial_number", "not_valid_after"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for item in inventory["cas"]:
        writer.writerow({"record_type": "ca", **item})
    for item in inventory["certificates"]:
        writer.writerow({"record_type": "certificate", **item})
    return Response(content=output.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=certificate-inventory.csv"})


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-") or "artifact"


@app.get(f"{API_PREFIX}/exports/package")
def export_package():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
        for ca in list_cas():
            stem = f"ca/{ca['id']}-{_safe_filename(ca['name'])}"
            package.writestr(f"{stem}.crt", ca["cert_pem"])
            package.writestr(f"{stem}.key", ca["key_pem"])
        for cert in list_certificates():
            stem = f"certificates/{cert['id']}-{_safe_filename(cert['domain'])}"
            package.writestr(f"{stem}.crt", cert["cert_pem"])
            package.writestr(f"{stem}.key", cert["key_pem"])
        for bundle in list_bundles_with_pem():
            package.writestr(f"bundles/{bundle['id']}-{_safe_filename(bundle['name'])}.pem", bundle["bundle_pem"])
        for material in list_trust_materials():
            stored = get_trust_material(material["id"])
            package.writestr(f"trust-materials/{material['id']}-{_safe_filename(material['name'])}.pem", stored["pem"])
        package.writestr("inventory.json", json.dumps(get_inventory(), indent=2))
    return Response(content=archive.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": "attachment; filename=qa-certificate-factory-artifacts.zip"})


@app.get(f"{API_PREFIX}/config-snippets/{{certificate_id}}")
def get_config_snippets(certificate_id: int):
    certificate = next((item for item in list_certificates() if item["id"] == certificate_id), None)
    if certificate is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    domain = certificate["domain"]
    cert_file = f"{certificate_id}-{_safe_filename(domain)}.crt"
    key_file = f"{certificate_id}-{_safe_filename(domain)}.key"
    return {
        "certificate_id": certificate_id,
        "domain": domain,
        "nginx": f"server {{\n    listen 443 ssl;\n    server_name {domain};\n    ssl_certificate /etc/ssl/{cert_file};\n    ssl_certificate_key /etc/ssl/{key_file};\n}}",
        "apache": f"<VirtualHost *:443>\n    ServerName {domain}\n    SSLEngine on\n    SSLCertificateFile /etc/ssl/{cert_file}\n    SSLCertificateKeyFile /etc/ssl/{key_file}\n</VirtualHost>",
        "rsyslog": f"# TLS listener for {domain}\nmodule(load=\"imtcp\")\ninput(type=\"imtcp\" port=\"6514\" StreamDriver.Name=\"gtls\" StreamDriver.Mode=\"1\" StreamDriver.AuthMode=\"anon\")",
        "openssl": f"openssl s_client -connect {domain}:443 -CAfile all-trusted-cas.pem -servername {domain}",
        "mtls_client": f"curl --cert {cert_file} --key {key_file} --cacert all-trusted-cas.pem https://{domain}/",
    }


@app.patch(f"{API_PREFIX}/ca/{{ca_id}}")
def update_ca_lifecycle(ca_id: int, payload: LifecycleUpdateRequest):
    if payload.status not in {None, "active", "revoked", "expired"}:
        raise HTTPException(status_code=400, detail="Status must be active, revoked, or expired")
    if payload.name is not None and not payload.name.strip():
        raise HTTPException(status_code=400, detail="CA name cannot be empty")
    if not update_ca(ca_id, name=payload.name.strip() if payload.name is not None else None, status=payload.status):
        raise HTTPException(status_code=404, detail="CA not found")
    return {"message": "CA updated"}


@app.patch(f"{API_PREFIX}/certificates/{{certificate_id}}")
def update_certificate_lifecycle(certificate_id: int, payload: LifecycleUpdateRequest):
    if payload.status not in {"active", "revoked", "expired"}:
        raise HTTPException(status_code=400, detail="Status must be active, revoked, or expired")
    if not update_certificate_status(certificate_id, payload.status):
        raise HTTPException(status_code=404, detail="Certificate not found")
    return {"message": "Certificate updated"}


@app.post(f"{API_PREFIX}/certificates/generate")
def generate_certificate(payload: CertificateGenerateRequest):
    if payload.ca_cert_pem and payload.ca_key_pem:
        ca_cert_pem, ca_key_pem = payload.ca_cert_pem, payload.ca_key_pem
    else:
        cas = list_cas()
        ca_row = next((item for item in cas if item["id"] == payload.ca_id), None)
        if ca_row is None:
            raise HTTPException(status_code=400, detail="CA material is required; create a CA in this session first")
        ca_cert_pem, ca_key_pem = ca_row["cert_pem"], ca_row["key_pem"]

    try:
        if payload.mode == "tls" and payload.role != "server":
            raise ValueError("TLS certificates must use the server role")
        if payload.mode == "mtls" and payload.role == "client" and payload.template_name != "mtls_client_auth":
            raise ValueError("mTLS client certificates require the mtls_client_auth template")
        if payload.mode == "mtls" and payload.role == "server" and payload.template_name == "mtls_client_auth":
            raise ValueError("mTLS server certificates require a server-auth template")
        cert_pem, key_pem = generate_leaf_certificate(
            ca_cert_pem=ca_cert_pem,
            ca_key_pem=ca_key_pem,
            domain=payload.domain,
            template_name=payload.template_name,
            validity_days=payload.validity_days,
            key_size=payload.key_size,
            san_domains=payload.san_domains,
        )
        if payload.ca_chain_pem:
            cert_pem += "\n" + bundle_ca_pem_files([payload.ca_chain_pem])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    cert_record = {"id": 0, "ca_id": payload.ca_id or 0, "domain": payload.domain, "template_name": payload.template_name}
    return {"message": "Certificate generated", "certificate": {**cert_record, "cert_pem": cert_pem, "key_pem": key_pem}}


@app.post(f"{API_PREFIX}/trust-materials/import")
def import_trust_material(payload: TrustMaterialImportRequest):
    try:
        pem = validate_trust_material(payload.pem, payload.material_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Trust material loaded for this session", "material": {"id": 0, "name": payload.name, "environment": payload.environment, "material_type": payload.material_type, "pem": pem}}


@app.get(f"{API_PREFIX}/trust-materials")
def get_trust_materials():
    return {"materials": list_trust_materials()}


@app.post(f"{API_PREFIX}/bundles/merge")
def merge_bundle(payload: BundleMergeRequest):
    pems = list(payload.ca_pems)
    cas = list_cas()
    for ca_id in payload.ca_ids:
        ca = next((item for item in cas if item["id"] == ca_id), None)
        if ca is None:
            raise HTTPException(status_code=404, detail=f"CA {ca_id} not found")
        pems.append(ca["cert_pem"])
    for material_id in payload.external_material_ids:
        material = get_trust_material(material_id)
        if material is None:
            raise HTTPException(status_code=404, detail=f"Trust material {material_id} not found")
        if material["material_type"] != "root_ca":
            raise HTTPException(status_code=400, detail="Only root CA materials can be added to a trust bundle")
        pems.append(material["pem"])
    try:
        merged = bundle_ca_pem_files(pems)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    bundle = {"id": 0, "name": payload.name, "mode": payload.mode}
    return {"message": "Bundle created", "bundle": {**bundle, "bundle_pem": merged}}


@app.get(f"{API_PREFIX}/bundles")
def get_bundles():
    return {"bundles": list_bundles()}


@app.post(f"{API_PREFIX}/trust-script")
def create_trust_script(payload: TrustScriptRequest):
    ca_cert_pem = payload.ca_cert_pem
    if not ca_cert_pem:
        cas = list_cas()
        ca_row = next((item for item in cas if item["id"] == payload.ca_id), None)
        if ca_row is None:
            raise HTTPException(status_code=400, detail="CA material is required; create a CA in this session first")
        ca_cert_pem = ca_row["cert_pem"]

    script = generate_trust_script(ca_cert_pem, payload.os_type)
    return {"script": script, "filename": f"install-trust-{payload.os_type}.{'bat' if payload.os_type.lower() == 'windows' else 'sh'}"}


@app.post(f"{API_PREFIX}/syslog/config")
def generate_syslog_config(payload: SyslogConfigRequest):
    auth_lines = 'StreamDriver.AuthMode="x509/name"\n    PermittedPeer="*"' if payload.mode == "mtls" else 'StreamDriver.AuthMode="anon"'
    config = f'''# Generated QA Certificate Factory rsyslog configuration
module(load="imuxsock")
module(load="imklog")
module(load="imudp")
module(load="imtcp")

global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="{payload.ca_path}"
    DefaultNetstreamDriverCertFile="{payload.cert_path}"
    DefaultNetstreamDriverKeyFile="{payload.key_path}")

template(name="DynamicFileUDP" type="list") {{
    constant(value="/var/log/remote/udp/")
    property(name="fromhost-ip")
    constant(value="/syslog.log")
}}
template(name="DynamicFileTCP" type="list") {{
    constant(value="/var/log/remote/tcp/")
    property(name="fromhost-ip")
    constant(value="/syslog.log")
}}
template(name="simple_raw_format" type="string" string="%rawmsg%\\n")

ruleset(name="remote_udp") {{
    action(type="omfile" dynaFile="DynamicFileUDP" template="simple_raw_format")
}}
ruleset(name="remote_tcp_tls") {{
    action(type="omfile" dynaFile="DynamicFileTCP" template="simple_raw_format")
}}

input(type="imudp" port="514" ruleset="remote_udp")
input(type="imtcp" port="6514" ruleset="remote_tcp_tls"
    StreamDriver.Name="gtls"
    StreamDriver.Mode="1"
    {auth_lines})

$CreateDirs on
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
'''
    return {"config": config, "filename": "rsyslog.conf"}


@app.post(f"{API_PREFIX}/certificates/verify")
def verify_certificate(payload: CertificateVerifyRequest):
    try:
        certificate = x509.load_pem_x509_certificate(payload.cert_pem.encode())
        ca = x509.load_pem_x509_certificate(payload.ca_cert_pem.encode())
        ca_basic = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        certificate_basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        ca.public_key().verify(certificate.signature, certificate.tbs_certificate_bytes, padding.PKCS1v15(), certificate.signature_hash_algorithm)
        now = datetime.datetime.now(datetime.timezone.utc)
        valid_dates = certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc
        issuer_matches = certificate.issuer == ca.subject
        hostname_matches = None
        names = []
        try:
            names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        if payload.hostname:
            hostname_matches = payload.hostname in names or any(name.startswith('*.') and payload.hostname.endswith(name[1:]) for name in names)
        usage = "unknown"
        try:
            eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku: usage = "server"
            elif x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku: usage = "client"
        except x509.ExtensionNotFound:
            pass
        role_matches = payload.expected_role is None or usage == payload.expected_role
        return {"valid": bool(ca_basic.ca and not certificate_basic.ca and issuer_matches and valid_dates and role_matches and (hostname_matches is not False)), "checks": {"signature": True, "issuer_matches": issuer_matches, "ca_is_ca": ca_basic.ca, "certificate_is_leaf": not certificate_basic.ca, "valid_dates": valid_dates, "hostname_matches": hostname_matches, "usage": usage, "role_matches": role_matches}, "sans": names}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Certificate verification failed: {exc}") from exc


@app.post(f"{API_PREFIX}/syslog/package")
def generate_syslog_package(payload: SyslogPackageRequest):
    if payload.include_client and (not payload.client_cert_pem or not payload.client_key_pem):
        raise HTTPException(status_code=400, detail="Both client certificate and client key are required")
    archive = io.BytesIO()
    instructions = f'''SYSLOG {payload.mode.upper()} SETUP

1. On the Linux syslog server, create the certificate directory:
   sudo mkdir -p /etc/rsyslog.d/keys

2. Copy these files into that directory:
   server.pem              - Server certificate presented by rsyslog.
   server.key              - Private key for server.pem; never share it.
   localca.pem             - The single public CA certificate that signed
                             server.pem. Install this certificate in every
                             client/AP trust store so clients can verify the
                             syslog server.
   all-trusted-cas.pem     - Public CA bundle used by rsyslog to verify peers.
                             TLS: contains the server CA.
                             mTLS: contains the server CA and Arista ca.pem.
   rsyslog.conf             - Rsyslog listener and TLS configuration.

3. Copy rsyslog.conf to /etc/rsyslog.conf. It points rsyslog at server.pem,
   server.key, and all-trusted-cas.pem.

4. Set permissions so rsyslog can read the certificates. Protect server.key
   more strictly because it is a private key.

5. Validate and restart rsyslog:
   sudo rsyslogd -N 1
   sudo systemctl restart rsyslog

{('mTLS AP setup: install the single localca.pem certificate in every AP trust store so APs can verify the syslog server. Each AP keeps its own existing client certificate and private key and presents that certificate to rsyslog. The Arista ca.pem is trusted by the server through all-trusted-cas.pem.' if payload.mode == 'mtls' else 'TLS setup: install the single localca.pem certificate in every client trust store so clients can verify the syslog server.')}

Never share server.key. Trust bundles contain public CA certificates only.
'''
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
        package.writestr("server.pem", payload.server_cert_pem)
        package.writestr("server.key", payload.server_key_pem)
        package.writestr("localca.pem", payload.server_ca_pem)
        package.writestr("all-trusted-cas.pem", payload.trust_bundle_pem)
        package.writestr("rsyslog.conf", payload.rsyslog_config)
        if payload.include_client:
            package.writestr("client.pem", payload.client_cert_pem)
            package.writestr("client.key", payload.client_key_pem)
        package.writestr("SETUP-INSTRUCTIONS.txt", instructions)
    package_filename = f"syslog-{payload.mode}-certificate-package.zip"
    return Response(content=archive.getvalue(), media_type="application/zip", headers={"Content-Disposition": f"attachment; filename={package_filename}"})
