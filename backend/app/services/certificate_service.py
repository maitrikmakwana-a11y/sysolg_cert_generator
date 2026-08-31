import datetime
import ipaddress
from typing import Dict, List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate_ca(name: str, environment: str) -> Tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QA Testing Team"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, environment),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem.decode("utf-8"), key_pem.decode("utf-8")


def _san_extension_for_domain(domain: str) -> x509.SubjectAlternativeName:
    return x509.SubjectAlternativeName([x509.DNSName(domain)])


def _template_profile(template_name: str) -> Dict[str, object]:
    profiles = {
        "standard_web_server": {
            "eku": [ExtendedKeyUsageOID.SERVER_AUTH],
            "wildcard": False,
            "days": 365,
        },
        "mtls_client_auth": {
            "eku": [ExtendedKeyUsageOID.CLIENT_AUTH],
            "wildcard": False,
            "days": 180,
        },
        "wildcard_domain": {
            "eku": [ExtendedKeyUsageOID.SERVER_AUTH],
            "wildcard": True,
            "days": 365,
        },
        "expired_cert": {
            "eku": [ExtendedKeyUsageOID.SERVER_AUTH],
            "wildcard": False,
            "days": -30,
        },
        "weak_key": {
            "eku": [ExtendedKeyUsageOID.SERVER_AUTH],
            "wildcard": False,
            "days": 365,
        },
    }
    if template_name not in profiles:
        raise ValueError(f"Unsupported template: {template_name}")
    return profiles[template_name]


def generate_leaf_certificate(ca_cert_pem: str, ca_key_pem: str, domain: str, template_name: str, validity_days: int = 365, key_size: int = 2048, san_domains: List[str] | None = None) -> Tuple[str, str]:
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode("utf-8"), password=None)
    profile = _template_profile(template_name)

    if template_name == "wildcard_domain":
        primary_domain = domain.strip()
        names = [primary_domain, f"*.{primary_domain}"] if "." in primary_domain else [f"*.{primary_domain}"]
    else:
        names = [domain.strip()]
    for san_domain in san_domains or []:
        value = san_domain.strip()
        if value and value not in names:
            names.append(value)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain.strip()),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QA Testing Team"),
    ])

    if template_name == "weak_key":
        key_size = 1024
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    now = datetime.datetime.now(datetime.timezone.utc)
    san_values = []
    for item in names:
        try:
            san_values.append(x509.IPAddress(ipaddress.ip_address(item)))
        except ValueError:
            san_values.append(x509.DNSName(item))
    days = profile.get("days") if template_name == "expired_cert" else validity_days
    if days < 0:
        not_valid_after = now - datetime.timedelta(days=abs(days))
    else:
        not_valid_after = now + datetime.timedelta(days=days)

    eku = list(profile["eku"])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(not_valid_after)
        .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem.decode("utf-8"), key_pem.decode("utf-8")


def bundle_ca_pem_files(ca_pems: List[str]) -> str:
    valid_blocks = []
    seen = set()
    for pem in ca_pems:
        value = pem.strip()
        if not value:
            continue
        remainder = value
        blocks = []
        while "-----BEGIN CERTIFICATE-----" in remainder:
            _, remainder = remainder.split("-----BEGIN CERTIFICATE-----", 1)
            if "-----END CERTIFICATE-----" not in remainder:
                raise ValueError("Invalid PEM certificate: missing end marker")
            body, remainder = remainder.split("-----END CERTIFICATE-----", 1)
            block = "-----BEGIN CERTIFICATE-----" + body.strip() + "\n-----END CERTIFICATE-----"
            try:
                x509.load_pem_x509_certificate(block.encode("utf-8"))
            except ValueError as exc:
                raise ValueError("Invalid PEM certificate") from exc
            if block not in seen:
                seen.add(block)
                blocks.append(block)
        if not blocks:
            raise ValueError("At least one valid PEM certificate is required")
        valid_blocks.extend(blocks)
    return "\n".join(valid_blocks) + "\n"


def validate_trust_material(pem: str, material_type: str) -> str:
    normalized = bundle_ca_pem_files([pem])
    remainder = normalized
    certificates = []
    while "-----BEGIN CERTIFICATE-----" in remainder:
        _, remainder = remainder.split("-----BEGIN CERTIFICATE-----", 1)
        body, remainder = remainder.split("-----END CERTIFICATE-----", 1)
        certificates.append(x509.load_pem_x509_certificate(("-----BEGIN CERTIFICATE-----" + body.strip() + "\n-----END CERTIFICATE-----").encode("utf-8")))
    is_ca = []
    for cert in certificates:
        try:
            is_ca.append(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        except x509.ExtensionNotFound:
            is_ca.append(False)
    if material_type == "root_ca" and not all(is_ca):
        raise ValueError("Root CA uploads must contain only CA certificates")
    if material_type == "client_certificate" and any(is_ca):
        raise ValueError("Client certificate uploads must not contain CA certificates")
    return normalized


def certificate_metadata(cert_pem: str) -> Dict[str, object]:
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    try:
        sans = [str(value) for value in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        sans = []
    return {
        "serial_number": format(cert.serial_number, "x"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "sans": sans,
        "is_ca": cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
    }


def list_available_templates() -> List[Dict[str, str]]:
    return [
        {"name": "standard_web_server", "description": "Standard web server certificate with server auth"},
        {"name": "mtls_client_auth", "description": "Client certificate template for mTLS and API gateways"},
        {"name": "wildcard_domain", "description": "Wildcard domain certificate for *.test.local scenarios"},
        {"name": "expired_cert", "description": "Expired certificate profile for edge-case testing"},
        {"name": "weak_key", "description": "Weak key profile for resilience testing"},
    ]
