import { useEffect, useState, type CSSProperties } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const API_KEY = import.meta.env.VITE_API_KEY || '';
const apiFetch = (url: string, init: RequestInit = {}) => fetch(url, {
  ...init,
  headers: { ...(init.headers || {}), ...(API_KEY ? { 'X-API-Key': API_KEY } : {}) },
});

type Template = {
  name: string;
  description: string;
};

type CA = {
  id: number;
  name: string;
  environment: string;
  cert_pem?: string;
  key_pem?: string;
};

type TrustMaterial = {
  id: number;
  name: string;
  environment: string;
  material_type: 'root_ca' | 'client_certificate';
  pem?: string;
};

type Inventory = {
  cas: Array<{ id: number; name: string; environment: string; status: string }>;
  certificates: Array<{ id: number; domain: string; template_name: string; status: string; not_valid_after: string }>;
};

function App() {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [cas, setCas] = useState<CA[]>([]);
  const [domain, setDomain] = useState('app.test.local');
  const [clientDomain, setClientDomain] = useState('syslog-client-01.qa.test.local');
  const [caId, setCaId] = useState<number | undefined>(undefined);
  const [templateName, setTemplateName] = useState('standard_web_server');
  const [mode, setMode] = useState<'' | 'tls' | 'mtls'>('');
  const [certificateRole, setCertificateRole] = useState<'server' | 'client' | 'existing'>('server');
  const [validityDays, setValidityDays] = useState(365);
  const [keySize, setKeySize] = useState(2048);
  const [additionalSANs, setAdditionalSANs] = useState('');
  const [ownCACert, setOwnCACert] = useState('');
  const [ownCAKey, setOwnCAKey] = useState('');
  const [caChain, setCaChain] = useState('');
  const [message, setMessage] = useState<string>('');
  const [result, setResult] = useState<string>('');
  const [generatedCert, setGeneratedCert] = useState<string>('');
  const [generatedKey, setGeneratedKey] = useState<string>('');
  const [serverCert, setServerCert] = useState<string>('');
  const [serverKey, setServerKey] = useState<string>('');
  const [clientCert, setClientCert] = useState<string>('');
  const [clientKey, setClientKey] = useState<string>('');
  const [caCertText, setCaCertText] = useState<string>('');
  const [caKeyText, setCaKeyText] = useState<string>('');
  const [scriptText, setScriptText] = useState<string>('');
  const [syslogConfig, setSyslogConfig] = useState<string>('');
  const [verification, setVerification] = useState<string>('');
  const [bundleText, setBundleText] = useState<string>('');
  const [bundleInput, setBundleInput] = useState<string>('');
  const [materials, setMaterials] = useState<TrustMaterial[]>([]);
  const [selectedBundleCAs, setSelectedBundleCAs] = useState<number[]>([]);
  const [selectedRoots, setSelectedRoots] = useState<number[]>([]);
  const [inventory, setInventory] = useState<Inventory>({ cas: [], certificates: [] });

  const fetchTemplates = async () => {
    const res = await apiFetch(`${API_BASE}/api/v1/templates`);
    const data = await res.json();
    setTemplates(data.templates || []);
  };

  const fetchCas = async () => {
    const res = await apiFetch(`${API_BASE}/api/v1/ca`);
    const data = await res.json();
    setCas(data.cas || []);
    if (data.cas?.length) {
      setCaId(data.cas[0].id);
    }
  };

  const fetchMaterials = async () => {
    const res = await apiFetch(`${API_BASE}/api/v1/trust-materials`);
    const data = await res.json();
    setMaterials(data.materials || []);
  };

  const fetchInventory = async () => {
    const res = await apiFetch(`${API_BASE}/api/v1/inventory`);
    const data = await res.json();
    setInventory({ cas: data.cas || [], certificates: data.certificates || [] });
  };

  useEffect(() => {
    fetchTemplates();
    fetchCas();
    fetchMaterials();
    fetchInventory();
  }, []);

  const createCA = async () => {
    const name = window.prompt('CA name', 'QA-Root-CA');
    const environment = window.prompt('Environment', 'QA');
    if (!name || !environment) return;

    const res = await apiFetch(`${API_BASE}/api/v1/ca`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, environment }),
    });

    const data = await res.json();
    setMessage(data.message || 'CA created');
    setCaCertText(data.ca.cert_pem || '');
    setCaKeyText(data.ca.key_pem || '');
    setCas([data.ca]);
    setCaId(data.ca.id);
    setInventory({ cas: [{ id: data.ca.id, name: data.ca.name, environment: data.ca.environment, status: 'active' }], certificates: [] });
  };

  const setLifecycleStatus = async (resource: 'ca' | 'certificates', id: number, status: string) => {
    setInventory((current) => ({ ...current, [resource === 'ca' ? 'cas' : 'certificates']: (resource === 'ca' ? current.cas : current.certificates).map((item) => item.id === id ? { ...item, status } : item) }));
    setMessage(`${resource === 'ca' ? 'CA' : 'Certificate'} marked ${status} for this session`);
  };

  const issueCertificate = async (role: 'server' | 'client') => {
    const selectedTemplate = role === 'client' ? 'mtls_client_auth' : 'standard_web_server';
    const certificateDomain = role === 'client' ? clientDomain : domain;
    const res = await apiFetch(`${API_BASE}/api/v1/certificates/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ca_id: caId, ca_cert_pem: caCertText, ca_key_pem: caKeyText, ca_chain_pem: caChain || undefined, domain: certificateDomain, template_name: selectedTemplate, mode: role === 'client' ? 'mtls' : 'tls', role, validity_days: validityDays, key_size: keySize, san_domains: additionalSANs.split(',').map((value) => value.trim()).filter(Boolean) }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Certificate generation failed');
    return data.certificate;
  };

  const generateCertificate = async () => {
    if (!mode) { setMessage('First choose TLS or mTLS'); return; }
    if (!caId) {
      setMessage('Create a CA first');
      return;
    }
    try {
      const certificate = await issueCertificate(certificateRole === 'client' ? 'client' : 'server');
      setGeneratedCert(certificate.cert_pem || '');
      setGeneratedKey(certificate.key_pem || '');
      if (certificateRole !== 'client') { setServerCert(certificate.cert_pem); setServerKey(certificate.key_pem); }
      else { setClientCert(certificate.cert_pem); setClientKey(certificate.key_pem); }
      setInventory((current) => ({ ...current, certificates: [{ id: Date.now(), domain: certificateRole === 'client' ? clientDomain : domain, template_name: certificateRole === 'client' ? 'mtls_client_auth' : 'standard_web_server', status: 'active', not_valid_after: new Date(Date.now() + validityDays * 86400000).toISOString() }, ...current.certificates] }));
      setMessage(`${certificateRole === 'client' ? 'Client' : 'Server'} certificate generated successfully`);
      setResult(`${certificate.cert_pem}\n\nPRIVATE KEY\n${certificate.key_pem}`);
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Certificate generation failed'); }
  };

  const generateMtlSPackage = async () => {
    if (!caId) { setMessage('Create or select a CA first'); return; }
    try {
      const generatedServer = await issueCertificate('server');
      if (certificateRole === 'existing') {
        setServerCert(generatedServer.cert_pem); setServerKey(generatedServer.key_pem);
        setInventory((current) => ({ ...current, certificates: [{ id: Date.now(), domain, template_name: 'standard_web_server', status: 'active', not_valid_after: new Date(Date.now() + validityDays * 86400000).toISOString() }, ...current.certificates] }));
        setGeneratedCert(generatedServer.cert_pem); setGeneratedKey(generatedServer.key_pem);
        setMessage('Server certificate generated. Use the AP Root CA for client verification.');
        return;
      }
      const generatedClient = await issueCertificate('client');
      setServerCert(generatedServer.cert_pem); setServerKey(generatedServer.key_pem);
      setClientCert(generatedClient.cert_pem); setClientKey(generatedClient.key_pem);
      setInventory((current) => ({ ...current, certificates: [
        { id: Date.now(), domain: clientDomain, template_name: 'mtls_client_auth', status: 'active', not_valid_after: new Date(Date.now() + validityDays * 86400000).toISOString() },
        { id: Date.now() + 1, domain, template_name: 'standard_web_server', status: 'active', not_valid_after: new Date(Date.now() + validityDays * 86400000).toISOString() },
        ...current.certificates,
      ] }));
      setGeneratedCert(generatedClient.cert_pem); setGeneratedKey(generatedClient.key_pem);
      setMessage('mTLS package certificates generated: server and client');
    } catch (error) { setMessage(error instanceof Error ? error.message : 'mTLS generation failed'); }
  };

  const finishMtlSSetup = async () => {
    if (mode !== 'mtls') { setMessage('Choose mTLS first'); return; }
    if (!caId || !caCertText || !caKeyText) { setMessage('Create or select your server CA first'); return; }
    if (certificateRole === 'existing' && !selectedRoots.length) { setMessage('Import and select the AP Root CA first'); return; }
    try {
      const generatedServer = await issueCertificate('server');
      setServerCert(generatedServer.cert_pem); setServerKey(generatedServer.key_pem);
      const selectedRootPems = materials.filter((item) => selectedRoots.includes(item.id) && item.pem).map((item) => item.pem as string);
      const bundleResponse = await apiFetch(`${API_BASE}/api/v1/bundles/merge`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'all-trusted-cas', mode: 'mtls', ca_pems: [caCertText, ...selectedRootPems], ca_ids: [], external_material_ids: [] }),
      });
      const bundleData = await bundleResponse.json();
      if (!bundleResponse.ok) throw new Error(bundleData.detail || 'Trust bundle generation failed');
      setBundleText(bundleData.bundle.bundle_pem || '');
      const configResponse = await apiFetch(`${API_BASE}/api/v1/syslog/config`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'mtls' }),
      });
      const configData = await configResponse.json();
      if (!configResponse.ok) throw new Error(configData.detail || 'rsyslog configuration generation failed');
      setSyslogConfig(configData.config || '');
      const packageResponse = await apiFetch(`${API_BASE}/api/v1/syslog/package`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'mtls', server_cert_pem: generatedServer.cert_pem, server_key_pem: generatedServer.key_pem, server_ca_pem: caCertText, trust_bundle_pem: bundleData.bundle.bundle_pem, rsyslog_config: configData.config }) });
      if (!packageResponse.ok) { const data = await packageResponse.json(); throw new Error(data.detail || 'Certificate package generation failed'); }
      const url = URL.createObjectURL(await packageResponse.blob()); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'syslog-mtls-certificate-package.zip'; anchor.click(); URL.revokeObjectURL(url);
      setMessage('mTLS setup complete. ZIP package downloaded.');
    } catch (error) { setMessage(error instanceof Error ? error.message : 'mTLS setup failed'); }
  };

  const importMaterial = async (event: React.ChangeEvent<HTMLInputElement>, materialType: 'root_ca' | 'client_certificate') => {
    const file = event.target.files?.[0];
    if (!file) return;
    const pem = await file.text();
    const name = window.prompt('Name for imported material', file.name.replace(/\.(pem|crt|cer)$/i, ''));
    if (!name) return;
    const res = await apiFetch(`${API_BASE}/api/v1/trust-materials/import`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, environment: 'External', material_type: materialType, pem }),
    });
    const data = await res.json();
    if (!res.ok) { setMessage(data.detail || 'Import failed'); return; }
    setMessage(`${materialType === 'root_ca' ? 'Root CA' : 'Client certificate'} imported`);
    setMaterials([...materials, { ...data.material, id: -(materials.length + 1) }]);
    event.target.value = '';
  };

  const useOwnCA = () => {
    if (!ownCACert || !ownCAKey) { setMessage('Choose both your CA certificate and CA private key first'); return; }
    const name = window.prompt('Name for your CA', 'My-Syslog-CA');
    if (!name) return;
    const ownCA = { id: Date.now(), name, environment: 'User supplied', cert_pem: ownCACert, key_pem: ownCAKey };
    setCas([ownCA]);
    setCaId(ownCA.id);
    setCaCertText(ownCACert);
    setCaKeyText(ownCAKey);
    setMessage('Your CA is ready for this session');
  };

  const downloadText = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const downloadExport = async (path: string, fallbackName: string) => {
    const res = await apiFetch(`${API_BASE}${path}`);
    if (!res.ok) { setMessage('Export failed'); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fallbackName;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const generateTrustScript = async () => {
    if (!caId) {
      setMessage('Create a CA first');
      return;
    }

    const res = await apiFetch(`${API_BASE}/api/v1/trust-script`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ca_id: caId, ca_cert_pem: caCertText, os_type: 'linux' }),
    });

    const data = await res.json();
    if (!res.ok) {
      setMessage(data.detail || 'Trust script generation failed');
      return;
    }

    setScriptText(data.script || '');
    setMessage('Trust script generated');
    downloadText(data.filename || 'install-trust.sh', data.script || '');
  };

  const generateSyslogConfig = async () => {
    if (!mode) { setMessage('Choose TLS or mTLS first'); return; }
    const res = await apiFetch(`${API_BASE}/api/v1/syslog/config`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }),
    });
    const data = await res.json();
    if (!res.ok) { setMessage(data.detail || 'Configuration generation failed'); return; }
    setSyslogConfig(data.config || '');
    downloadText(data.filename || 'rsyslog.conf', data.config || '');
    setMessage('rsyslog.conf generated');
  };

  const verifyCurrentCertificate = async () => {
    if (!generatedCert || !caCertText) { setMessage('Generate a certificate first'); return; }
    const response = await apiFetch(`${API_BASE}/api/v1/certificates/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cert_pem: generatedCert, ca_cert_pem: caCertText, hostname: certificateRole === 'client' ? clientDomain : domain, expected_role: certificateRole === 'client' ? 'client' : 'server' }) });
    const data = await response.json();
    if (!response.ok) { setMessage(data.detail || 'Verification failed'); return; }
    setVerification(data.valid ? 'Certificate is valid for this CA and purpose.' : 'Certificate needs attention. Review the checks below.');
    setMessage(data.valid ? 'Certificate verification passed' : 'Certificate verification found an issue');
  };

  const downloadSyslogPackage = async () => {
    if (!mode || !serverCert || !serverKey || !caCertText || !bundleText || !syslogConfig) {
      setMessage('Generate the server certificate, trust bundle, and rsyslog configuration first'); return;
    }
    const response = await apiFetch(`${API_BASE}/api/v1/syslog/package`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode, server_cert_pem: serverCert, server_key_pem: serverKey, server_ca_pem: caCertText, trust_bundle_pem: bundleText, rsyslog_config: syslogConfig, include_client: mode === 'mtls' && Boolean(clientCert && clientKey), client_cert_pem: clientCert || undefined, client_key_pem: clientKey || undefined }) });
    if (!response.ok) { const data = await response.json(); setMessage(data.detail || 'Package generation failed'); return; }
    const url = URL.createObjectURL(await response.blob());
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'syslog-certificate-package.zip'; anchor.click(); URL.revokeObjectURL(url);
    setMessage('Complete syslog package downloaded');
  };

  const validateAndDownloadPackage = async () => {
    if (!mode || !serverCert || !serverKey || !caCertText) { setMessage('First generate the server certificate and CA'); return; }
    if (mode === 'mtls' && certificateRole === 'existing' && !selectedRoots.length) { setMessage('Import and select the AP Root CA first'); return; }
    let preparedBundle = bundleText;
    let preparedConfig = syslogConfig;
    try {
      if (!preparedBundle) {
        const roots = materials.filter((item) => selectedRoots.includes(item.id) && item.pem).map((item) => item.pem as string);
        const bundleResponse = await apiFetch(`${API_BASE}/api/v1/bundles/merge`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'all-trusted-cas', mode, ca_pems: [caCertText, ...roots], ca_ids: [], external_material_ids: [] }) });
        const bundleData = await bundleResponse.json();
        if (!bundleResponse.ok) throw new Error(bundleData.detail || 'Trust bundle generation failed');
        preparedBundle = bundleData.bundle.bundle_pem; setBundleText(preparedBundle);
      }
      if (!preparedConfig) {
        const configResponse = await apiFetch(`${API_BASE}/api/v1/syslog/config`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }) });
        const configData = await configResponse.json();
        if (!configResponse.ok) throw new Error(configData.detail || 'rsyslog configuration generation failed');
        preparedConfig = configData.config; setSyslogConfig(preparedConfig);
      }
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Could not prepare download files'); return; }
    const response = await apiFetch(`${API_BASE}/api/v1/certificates/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cert_pem: serverCert, ca_cert_pem: caCertText, hostname: domain, expected_role: 'server' }) });
    const result = await response.json();
    if (!response.ok || !result.valid) { setMessage(result.detail || 'Preflight failed: check the server certificate and hostname'); return; }
    const packageResponse = await apiFetch(`${API_BASE}/api/v1/syslog/package`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode, server_cert_pem: serverCert, server_key_pem: serverKey, server_ca_pem: caCertText, trust_bundle_pem: preparedBundle, rsyslog_config: preparedConfig, include_client: mode === 'mtls' && certificateRole !== 'existing' && Boolean(clientCert && clientKey), client_cert_pem: clientCert || undefined, client_key_pem: clientKey || undefined }) });
    if (!packageResponse.ok) { const data = await packageResponse.json(); setMessage(data.detail || 'Package generation failed'); return; }
    const url = URL.createObjectURL(await packageResponse.blob()); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'syslog-certificate-package.zip'; anchor.click(); URL.revokeObjectURL(url);
    setMessage('Everything is ready. Complete syslog package downloaded.');
  };

  const mergeBundle = async () => {
    const pemList = bundleInput
      .split('-----BEGIN CERTIFICATE-----')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => `-----BEGIN CERTIFICATE-----${part}`)
      .filter((part) => part.includes('BEGIN CERTIFICATE'));

    const selectedLocalCAPems = cas.filter((item) => selectedBundleCAs.includes(item.id) && item.cert_pem).map((item) => item.cert_pem as string);
    const selectedImportedRootPems = materials.filter((item) => selectedRoots.includes(item.id) && item.pem).map((item) => item.pem as string);
    const currentServerCAPem = caCertText && !selectedLocalCAPems.length ? [caCertText] : [];
    if (!pemList.length && !selectedLocalCAPems.length && !selectedImportedRootPems.length && !currentServerCAPem.length) {
      setMessage('Select a CA/imported root or paste a PEM certificate before merging');
      return;
    }

    const res = await apiFetch(`${API_BASE}/api/v1/bundles/merge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'all-trusted-cas', mode: mode || 'tls', ca_pems: [...pemList, ...selectedLocalCAPems, ...currentServerCAPem, ...selectedImportedRootPems], ca_ids: [], external_material_ids: [] }),
    });

    const data = await res.json();
    if (!res.ok) {
      setMessage(data.detail || 'Bundle merge failed');
      return;
    }

    setBundleText(data.bundle.bundle_pem || '');
    setMessage('CA bundle merged successfully');
    downloadText('all-trusted-cas.pem', data.bundle.bundle_pem || '');
  };

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', padding: 24, color: '#e2e8f0' }}>
      <h1 style={{ fontSize: 32, marginBottom: 16 }}>QA Certificate Factory</h1>

      <details style={{ background: '#172554', borderRadius: 12, padding: 20, border: '1px solid #3b82f6', marginBottom: 24 }}>
        <summary style={{ cursor: 'pointer', fontSize: 20, fontWeight: 700 }}>Simple help: set up TLS or mTLS for your syslog server</summary>
        <div style={{ color: '#dbeafe', lineHeight: 1.6, marginTop: 16 }}>
          <p style={{ fontSize: 16, marginTop: 0 }}>First choose the security level you need:</p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
            <div style={{ ...helpCardStyle, borderColor: '#38bdf8' }}><h3 style={{ marginTop: 0 }}>🔒 TLS</h3><p><strong>Use when:</strong> APs only need to verify the syslog server.</p><p style={{ marginBottom: 0 }}><strong>Give to the AP:</strong> your server CA certificate.</p></div>
            <div style={{ ...helpCardStyle, borderColor: '#c084fc' }}><h3 style={{ marginTop: 0 }}>🔐 mTLS</h3><p><strong>Use when:</strong> the server must verify every AP too.</p><p style={{ marginBottom: 0 }}><strong>Give to the server:</strong> the AP Root CA.</p></div>
          </div>
          <h3>mTLS with APs that already have certificates</h3>
          <div style={{ display: 'grid', gap: 8 }}>{['Select mTLS.', 'Select “AP already has its client certificate”.', 'Generate the server certificate.', 'Import the AP Root CA—the CA that signed the AP certificate.', 'Build the trust bundle with your server CA and the AP Root CA.', 'Install the server files on rsyslog and your server CA in each AP trust store.'].map((step, index) => <div key={step} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}><span style={stepBadgeStyle}>{index + 1}</span><span>{step}</span></div>)}</div>
          <div style={{ ...guideStyle, marginTop: 14 }}><strong>You do not need every AP certificate.</strong> Each AP sends its own client certificate during connection. The server only needs the AP Root CA to validate certificates issued by it.</div>
          <h3>Files at a glance</h3>
          <div style={{ display: 'grid', gap: 6 }}>{[['server.pem', 'Install on the syslog server'], ['server.key', 'Secret key for the syslog server'], ['localca.pem', 'Your public server CA; install in AP trust stores'], ['all-trusted-cas.pem', 'Public CA bundle used by the server to trust APs']].map(([file, purpose]) => <div key={file} style={fileRowStyle}><code>{file}</code><span>{purpose}</span></div>)}</div>
          <p style={{ marginBottom: 0 }}><strong>Naming:</strong> use <code>QA-Syslog-CA</code>, <code>syslog.qa.test.local</code>, and <code>ap-01.qa.test.local</code>. Do not include <code>https://</code> or a port.</p>
        </div>
      </details>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16, marginBottom: 24 }}>
        <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155' }}>
          <h3>Environment Roots</h3>
          <p>{cas.length} CA(s) available</p>
          <button onClick={createCA} style={buttonStyle}>Create CA</button>
        </div>

        <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155' }}>
          <h3>Templates</h3>
          <p>{templates.length} profile presets available</p>
        </div>

        <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155' }}>
          <h3>mTLS / TLS</h3>
          <p>Supports TCP/TLS 6514 and mTLS trust bundles</p>
        </div>
      </div>

      <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155', marginBottom: 24 }}>
        <h2 style={{ marginTop: 0 }}>Generate certificate</h2>

        <label style={{ display: 'block', marginBottom: 16 }}>
          1. Choose your setup
          <select value={mode} onChange={(e) => { const next = e.target.value as '' | 'tls' | 'mtls'; setMode(next); setCertificateRole('server'); if (next === 'mtls') setTemplateName('standard_web_server'); if (next === 'tls') setTemplateName('standard_web_server'); }} style={inputStyle}>
            <option value="">Select TLS or mTLS...</option>
            <option value="tls">TLS (server certificate)</option>
            <option value="mtls">mTLS (client certificate)</option>
          </select>
          <small style={{ display: 'block', color: '#94a3b8', marginTop: 6 }}>{!mode ? 'Choose a mode to show the relevant options.' : mode === 'tls' ? 'Clients verify the syslog server.' : 'The syslog server verifies every client too.'}</small>
        </label>

        {mode === 'tls' && <div style={guideStyle}><strong>TLS plan:</strong> create/select the syslog CA, generate one server certificate, then install the public CA certificate on every syslog client.</div>}
        {mode === 'mtls' && <div style={guideStyle}><strong>mTLS plan:</strong> generate the server certificate here, then import or create client certificates separately. The server trusts the client CA; each client trusts the server CA.</div>}

        {mode && <>
        {mode === 'mtls' && <label style={{ display: 'block', marginBottom: 16 }}>
          2. What do you want to generate?
          <select value={certificateRole} onChange={(e) => { const next = e.target.value as 'server' | 'client' | 'existing'; setCertificateRole(next); setTemplateName(next === 'client' ? 'mtls_client_auth' : 'standard_web_server'); }} style={inputStyle}>
            <option value="server">The syslog server certificate</option>
            <option value="client">A client certificate</option>
            <option value="existing">AP already has its client certificate</option>
          </select>
          <small style={{ display: 'block', color: '#94a3b8', marginTop: 6 }}>{certificateRole === 'server' ? 'Install this on the syslog server.' : certificateRole === 'client' ? 'Give this certificate and its private key to one approved client.' : 'Do not generate a client certificate. Import the AP Root CA below so the server can trust existing AP certificates.'}</small>
        </label>}
        <label style={{ display: 'block', marginBottom: 16 }}>
          {mode === 'mtls' ? '3' : '2'}. Select the issuing CA
          <select value={caId ?? ''} onChange={(e) => setCaId(Number(e.target.value))} style={inputStyle}>
            {cas.map((item) => (
              <option key={item.id} value={item.id}>{item.name} ({item.environment})</option>
            ))}
          </select>
        </label>

        <label style={{ display: 'block', marginBottom: 16 }}>
          {mode === 'mtls' ? '4' : '3'}. Certificate type
          <select value={templateName} onChange={(e) => setTemplateName(e.target.value)} style={inputStyle}>
            {templates.map((template) => (
              <option key={template.name} value={template.name}>{template.name}</option>
            ))}
          </select>
          <small style={{ display: 'block', color: '#94a3b8', marginTop: 6 }}>Server auth identifies a service; client auth identifies an application or device.</small>
        </label>

        <label style={{ display: 'block', marginBottom: 16 }}>
          {mode === 'mtls' ? '5' : '4'}. {mode === 'tls' || certificateRole === 'server' ? 'Syslog server hostname' : 'Client name'}
          <input value={domain} onChange={(e) => setDomain(e.target.value)} style={inputStyle} />
          <small style={{ display: 'block', color: '#94a3b8', marginTop: 6 }}>Use the exact hostname clients will connect to. Include no protocol or port.</small>
        </label>

        {mode === 'mtls' && <label style={{ display: 'block', marginBottom: 16 }}>Client identity name
          <input value={clientDomain} onChange={(e) => setClientDomain(e.target.value)} style={inputStyle} />
          <small style={{ display: 'block', color: '#94a3b8', marginTop: 6 }}>Used when generating the client certificate or the complete mTLS pair.</small>
        </label>}

        <details style={{ marginBottom: 16, color: '#cbd5e1' }}>
          <summary style={{ cursor: 'pointer', color: '#93c5fd' }}>Advanced certificate settings (optional)</summary>
          <div style={{ marginTop: 12 }}>
            <label style={{ display: 'block', marginBottom: 12 }}>Certificate lifetime (days)
              <input type="number" min="1" max="3650" value={validityDays} onChange={(e) => setValidityDays(Number(e.target.value))} style={inputStyle} />
            </label>
            <label style={{ display: 'block', marginBottom: 12 }}>RSA key size
              <select value={keySize} onChange={(e) => setKeySize(Number(e.target.value))} style={inputStyle}>
                <option value={2048}>2048-bit (recommended for QA)</option><option value={4096}>4096-bit (stronger, slower)</option>
              </select>
            </label>
            <label style={{ display: 'block' }}>Additional DNS names (optional)
              <input value={additionalSANs} onChange={(e) => setAdditionalSANs(e.target.value)} placeholder="syslog-1.qa.test.local,logs.qa.test.local" style={inputStyle} />
              <small style={{ display: 'block', color: '#94a3b8', marginTop: 6 }}>Comma-separated names that should also work for this certificate.</small>
            </label>
            <label style={{ display: 'block', marginTop: 12 }}>Intermediate CA chain (optional)
              <input type="file" accept=".pem,.crt,.cer" onChange={async (e) => { const file = e.target.files?.[0]; if (file) setCaChain(await file.text()); }} style={{ ...inputStyle, padding: 8 }} />
              <small style={{ display: 'block', color: '#94a3b8', marginTop: 6 }}>Upload public intermediate certificates if your CA uses Root CA → Intermediate CA → server/client certificate.</small>
            </label>
          </div>
        </details>

        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <button onClick={generateCertificate} style={buttonStyle}>{mode === 'mtls' ? '6' : '5'}. Generate {certificateRole === 'client' ? 'client' : 'server'} certificate</button>
          {mode === 'mtls' && <button onClick={generateMtlSPackage} style={{ ...buttonStyle, background: '#9333ea' }}>{certificateRole === 'existing' ? 'Generate server certificate' : 'Generate both server + client'}</button>}
          {mode === 'mtls' && <button onClick={finishMtlSSetup} style={{ ...buttonStyle, background: '#16a34a' }}>Finish mTLS setup</button>}
          <button onClick={generateTrustScript} style={{ ...buttonStyle, background: '#0f766e' }}>Download trust script</button>
        </div>
        </>}
        {!mode && <p style={{ color: '#94a3b8' }}>Start by selecting TLS or mTLS above.</p>}
        <p style={{ marginTop: 12 }}>{message}</p>
      </div>

      {mode && <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155', marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
          <h2 style={{ marginTop: 0 }}>Certificate inventory</h2>
          <button onClick={fetchInventory} style={{ ...buttonStyle, background: '#475569' }}>Refresh</button>
        </div>
        <h3>Certificate Authorities ({inventory.cas.length})</h3>
        {inventory.cas.map((item) => <div key={item.id} style={inventoryRowStyle}>
          <span><strong>{item.name}</strong> · {item.environment} · <Status status={item.status} /></span>
          {item.status === 'active' && <button onClick={() => setLifecycleStatus('ca', item.id, 'revoked')} style={smallButtonStyle}>Revoke</button>}
        </div>)}
        <h3>Issued certificates ({inventory.certificates.length})</h3>
        {inventory.certificates.map((item) => <div key={item.id} style={inventoryRowStyle}>
          <span><strong>{item.domain}</strong> · {item.template_name} · expires {new Date(item.not_valid_after).toLocaleDateString()} · <Status status={item.status} /></span>
          {item.status === 'active' && <button onClick={() => setLifecycleStatus('certificates', item.id, 'revoked')} style={smallButtonStyle}>Revoke</button>}
        </div>)}
        {!inventory.cas.length && !inventory.certificates.length && <p style={{ color: '#94a3b8' }}>No inventory records yet.</p>}
      </div>}

      <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155', marginBottom: 24 }}>
        <h2 style={{ marginTop: 0 }}>Download everything</h2>
        <p style={{ color: '#cbd5e1' }}>One ZIP file contains the correct certificates, keys, trust bundle, rsyslog configuration, and setup instructions for your selected mode.</p>
        <div style={guideStyle}><strong>Package contents:</strong> server files, <code>localca.pem</code>, <code>all-trusted-cas.pem</code>, <code>rsyslog.conf</code>, and <code>SETUP-INSTRUCTIONS.txt</code>. Existing-AP mTLS packages do not include unnecessary client files.</div>
        <button onClick={validateAndDownloadPackage} style={{ ...buttonStyle, background: '#16a34a', fontSize: 16 }} disabled={!mode}>Validate & download everything</button>
        {verification && <p style={{ ...guideStyle, marginTop: 14 }}>{verification}</p>}
      </div>

      <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155', marginBottom: 24 }}>
        <h2 style={{ marginTop: 0 }}>Linux rsyslog server checklist</h2>
        <p style={{ color: '#cbd5e1' }}>This matches the supplied <code>Linux-remote-syslog-setup.txt</code> guide.</p>
        <ol style={{ color: '#cbd5e1', lineHeight: 1.7 }}>
          <li>Install and enable rsyslog.</li>
          <li>Create <code>/etc/rsyslog.d/keys/</code> and copy <code>server.pem</code>, <code>server.key</code>, and <code>all-trusted-cas.pem</code> there.</li>
          <li>Set certificate permissions to <code>644</code>; protect the private key more strictly when possible.</li>
          <li>Set the rsyslog TLS paths to those three filenames, then run <code>sudo rsyslogd -N 1</code>.</li>
          <li>Restart with <code>sudo systemctl restart rsyslog</code>. The server listens on UDP 514 and TCP/TLS 6514.</li>
        </ol>
        <div style={guideStyle}><strong>What does the bundle do?</strong> <code>all-trusted-cas.pem</code> contains public CA certificates trusted by rsyslog. Include the AP/external CA and the local CA when both kinds of clients will connect. Do not put server or client private keys in this file.</div>
      </div>

      {syslogConfig && <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155', marginBottom: 24 }}>
        <h2 style={{ marginTop: 0 }}>Generated rsyslog.conf</h2>
        <p style={{ color: '#94a3b8' }}>Copy this file to <code>/etc/rsyslog.conf</code> after placing the certificates in the keys directory.</p>
        <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12, background: '#020617', padding: 16, borderRadius: 8, color: '#cbd5e1', maxHeight: 300, overflow: 'auto' }}>{syslogConfig}</pre>
      </div>}

      {mode && <>
      <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155', marginBottom: 24 }}>
        <h2 style={{ marginTop: 0 }}>Optional: use certificates from somewhere else</h2>
        <p style={{ color: '#cbd5e1' }}>Skip this section if you created the CA above. Use it only when your syslog setup already has certificates.</p>
        <p style={{ color: '#94a3b8' }}><strong>To generate new certificates with your own CA, choose both files below.</strong> The CA certificate is public; the CA private key is required for signing and stays only in this browser session.</p>
        <div style={{ display: 'grid', gap: 10, maxWidth: 520, marginBottom: 14 }}>
          <label style={fileLabelStyle}>Your CA certificate (.pem/.crt)<input type="file" accept=".pem,.crt,.cer" onChange={async (e) => { const file = e.target.files?.[0]; if (file) setOwnCACert(await file.text()); }} /></label>
          <label style={fileLabelStyle}>Your CA private key (.key/.pem)<input type="file" accept=".key,.pem" onChange={async (e) => { const file = e.target.files?.[0]; if (file) setOwnCAKey(await file.text()); }} /></label>
          <button onClick={useOwnCA} style={{ ...buttonStyle, width: 'fit-content' }}>Use my CA for this session</button>
        </div>
        <p style={{ color: '#94a3b8' }}><strong>For your AP setup:</strong> import the AP/client Root CA here. Add it to the server trust bundle so the server can verify the client certificate presented by every AP. The AP keeps its own client certificate and key.</p>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <label style={buttonStyle}>I already have a Root CA<input type="file" accept=".pem,.crt,.cer" onChange={(e) => importMaterial(e, 'root_ca')} style={{ display: 'none' }} /></label>
          <label style={{ ...buttonStyle, background: '#7c3aed' }}>I already have a client certificate<input type="file" accept=".pem,.crt,.cer" onChange={(e) => importMaterial(e, 'client_certificate')} style={{ display: 'none' }} /></label>
        </div>
        {materials.length > 0 && <div style={{ marginTop: 16 }}>
          {materials.map((material) => <div key={material.id} style={{ margin: '8px 0', color: '#cbd5e1' }}>
            {material.material_type === 'root_ca' && <input type="checkbox" checked={selectedRoots.includes(material.id)} onChange={(e) => setSelectedRoots(e.target.checked ? [...selectedRoots, material.id] : selectedRoots.filter((id) => id !== material.id))} />}
            <span style={{ marginLeft: 8 }}>{material.name} ({material.material_type})</span>
          </div>)}
        </div>}
      </div>

      <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155', marginBottom: 24 }}>
        <h2 style={{ marginTop: 0 }}>Create the trust bundle</h2>
        <p style={{ color: '#cbd5e1' }}>A trust bundle is a file containing public CA certificates. Give it to the side that needs to verify a certificate.</p>
        <p style={{ color: '#94a3b8' }}>For TLS, include the syslog server’s CA and give the bundle to clients. For your mTLS AP setup, include the AP Root CA for the server and your server CA for the APs. Never include private keys or client certificates here.</p>
        {cas.map((item) => <label key={item.id} style={{ display: 'block', margin: '8px 0' }}><input type="checkbox" checked={selectedBundleCAs.includes(item.id)} onChange={(e) => setSelectedBundleCAs(e.target.checked ? [...selectedBundleCAs, item.id] : selectedBundleCAs.filter((id) => id !== item.id))} /> <span style={{ marginLeft: 8 }}>{item.name} ({item.environment})</span></label>)}
        <textarea
          value={bundleInput}
          onChange={(e) => setBundleInput(e.target.value)}
          placeholder="Paste one or more PEM certificates here..."
          style={{ ...inputStyle, minHeight: 150, resize: 'vertical' }}
        />
        <div style={{ marginTop: 12 }}>
          <button onClick={mergeBundle} style={{ ...buttonStyle, background: '#ea580c' }}>Merge trusted CA bundle</button>
        </div>
        {bundleText && (
          <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12, background: '#020617', padding: 16, borderRadius: 8, color: '#cbd5e1', marginTop: 16 }}>
            {bundleText}
          </pre>
        )}
      </div>
      </>}

      <div style={{ background: '#111827', borderRadius: 12, padding: 20, border: '1px solid #334155' }}>
        <h2 style={{ marginTop: 0 }}>Generated result</h2>
        <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12, background: '#020617', padding: 16, borderRadius: 8, color: '#cbd5e1' }}>
          {result || 'No certificate generated yet.'}
        </pre>
      </div>
    </div>
  );
}

const inputStyle: CSSProperties = {
  width: '100%',
  padding: '10px 12px',
  marginTop: 8,
  borderRadius: 8,
  border: '1px solid #475569',
  background: '#020617',
  color: '#e2e8f0',
};

const buttonStyle: CSSProperties = {
  background: '#2563eb',
  color: 'white',
  padding: '10px 16px',
  border: 'none',
  borderRadius: 8,
  cursor: 'pointer',
  fontWeight: 600,
};

const smallButtonStyle: CSSProperties = { ...buttonStyle, padding: '6px 10px', fontSize: 12, background: '#991b1b' };
const guideStyle: CSSProperties = { background: '#0f2d45', color: '#dbeafe', border: '1px solid #2563eb', borderRadius: 8, padding: 12, marginBottom: 16, lineHeight: 1.5 };
const helpCardStyle: CSSProperties = { background: '#0f172a', border: '1px solid', borderRadius: 10, padding: 14 };
const stepBadgeStyle: CSSProperties = { minWidth: 24, height: 24, borderRadius: '50%', background: '#2563eb', color: 'white', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 13 };
const fileRowStyle: CSSProperties = { display: 'flex', justifyContent: 'space-between', gap: 12, padding: '8px 10px', background: '#0f172a', borderRadius: 6 };
const fileLabelStyle: CSSProperties = { display: 'grid', gap: 6, color: '#cbd5e1', fontSize: 14 };
const inventoryRowStyle: CSSProperties = { display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center', padding: '10px 0', borderBottom: '1px solid #1e293b', fontSize: 14 };

function Status({ status }: { status: string }) {
  return <span style={{ color: status === 'active' ? '#4ade80' : '#fbbf24' }}>{status}</span>;
}

export default App;
