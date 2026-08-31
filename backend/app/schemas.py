from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class CACreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    environment: str = Field(..., min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")


class CertificateGenerateRequest(BaseModel):
    ca_id: Optional[int] = None
    ca_cert_pem: Optional[str] = None
    ca_key_pem: Optional[str] = None
    domain: str = Field(..., min_length=1, max_length=253, pattern=r"^[A-Za-z0-9*][A-Za-z0-9*.-]*$")
    template_name: str = Field(default="standard_web_server")
    validity_days: int = Field(default=365, ge=1)
    mode: str = Field(default="tls", pattern="^(tls|mtls)$")
    role: str = Field(default="server", pattern="^(server|client)$")
    key_size: Literal[1024, 2048, 4096] = 2048
    san_domains: List[str] = Field(default_factory=list, max_length=20)
    ca_chain_pem: Optional[str] = None


class TrustMaterialImportRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    environment: str = Field(default="External", min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    material_type: str = Field(..., pattern="^(root_ca|client_certificate)$")
    pem: str = Field(..., min_length=1)


class LifecycleUpdateRequest(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None


class BundleMergeRequest(BaseModel):
    name: str = Field(..., min_length=1)
    mode: str = Field(default="tls")
    ca_pems: List[str] = Field(default_factory=list)
    ca_ids: List[int] = Field(default_factory=list)
    external_material_ids: List[int] = Field(default_factory=list)


class TrustScriptRequest(BaseModel):
    ca_id: Optional[int] = None
    ca_cert_pem: Optional[str] = None
    os_type: str = Field(default="linux")


class SyslogConfigRequest(BaseModel):
    mode: str = Field(default="tls", pattern="^(tls|mtls)$")
    ca_path: str = Field(default="/etc/rsyslog.d/keys/all-trusted-cas.pem", max_length=300)
    cert_path: str = Field(default="/etc/rsyslog.d/keys/server.pem", max_length=300)
    key_path: str = Field(default="/etc/rsyslog.d/keys/server.key", max_length=300)


class CertificateVerifyRequest(BaseModel):
    cert_pem: str = Field(..., min_length=1)
    ca_cert_pem: str = Field(..., min_length=1)
    hostname: Optional[str] = None
    expected_role: Optional[str] = Field(default=None, pattern="^(server|client)$")


class SyslogPackageRequest(BaseModel):
    mode: str = Field(default="tls", pattern="^(tls|mtls)$")
    server_cert_pem: str = Field(..., min_length=1)
    server_key_pem: str = Field(..., min_length=1)
    server_ca_pem: str = Field(..., min_length=1)
    trust_bundle_pem: str = Field(..., min_length=1)
    rsyslog_config: str = Field(..., min_length=1)
    include_client: bool = False
    client_cert_pem: Optional[str] = None
    client_key_pem: Optional[str] = None


class CertificateResponse(BaseModel):
    id: int
    ca_id: int
    domain: str
    template_name: str
    cert_pem: str
    key_pem: str


class CAResponse(BaseModel):
    id: int
    name: str
    environment: str
    cert_pem: Optional[str] = None
    key_pem: Optional[str] = None


class BundleResponse(BaseModel):
    id: int
    name: str
    mode: str
    bundle_pem: str
