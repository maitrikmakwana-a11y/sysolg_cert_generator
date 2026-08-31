def generate_trust_script(ca_pem: str, os_type: str) -> str:
    if os_type.lower() == "windows":
        return f"@echo off\r\nset CERT_FILE=%TEMP%\\qa-root-ca.pem\r\n" \
               f"echo {ca_pem.strip()} > %CERT_FILE%\r\n" \
               "certutil -addstore -enterprise root %CERT_FILE%\r\n" \
               "del %CERT_FILE%\r\n"

    return f"#!/usr/bin/env bash\n" \
           "set -e\n" \
           "CERT_FILE=$(mktemp)\n" \
           f"cat > \"$CERT_FILE\" <<'EOF'\n{ca_pem.strip()}\nEOF\n" \
           "sudo cp \"$CERT_FILE\" /usr/local/share/ca-certificates/qa-root-ca.crt\n" \
           "sudo update-ca-certificates\n" \
           "rm -f \"$CERT_FILE\"\n"
