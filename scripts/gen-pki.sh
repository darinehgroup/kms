#!/usr/bin/env bash
# Internal PKI for KMS mTLS (design.md §10).
#
# RUN THIS ON AN OFFLINE/SEPARATE ADMIN MACHINE. The CA key (ca.key) must
# never be copied to the KMS or App servers — only the leaf certs/keys and
# ca.crt are deployed.
#
# Usage: gen-pki.sh <out-dir> <kms-private-ip>
# Leaf certificates are valid 1 year; re-run yearly and update the pins.
set -euo pipefail

DIR=${1:?usage: gen-pki.sh <out-dir> <kms-private-ip>}
KMS_IP=${2:?usage: gen-pki.sh <out-dir> <kms-private-ip>}

mkdir -p "$DIR"
cd "$DIR"
umask 077

# --- CA (10 years, offline) -------------------------------------------------
if [[ ! -f ca.key ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out ca.key
    openssl req -new -x509 -key ca.key -sha256 -days 3650 \
        -subj "/CN=Finomix Internal KMS CA" -out ca.crt \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    echo "created CA (ca.key stays on this machine only)"
fi

issue_leaf() { # name, extensions
    local name=$1 ext=$2
    openssl ecparam -name prime256v1 -genkey -noout -out "$name.key"
    openssl req -new -key "$name.key" -subj "/CN=$name" -out "$name.csr"
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 365 -sha256 -extfile <(printf '%s\n' "$ext") -out "$name.crt"
    rm -f "$name.csr"
}

# --- server leaf (SAN = KMS private IP) --------------------------------------
issue_leaf kms-server "subjectAltName=IP:$KMS_IP
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth"

# --- client leaf (App server) -------------------------------------------------
issue_leaf app-client "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth"

rm -f ca.srl

pin() { openssl x509 -in "$1" -outform der | openssl dgst -sha256 -hex | awk '{print $NF}'; }

echo
echo "Deploy to the KMS server:  kms-server.crt kms-server.key ca.crt   -> /etc/kms/"
echo "Deploy to the App server:  app-client.crt app-client.key ca.crt   -> /opt/finomix/kms/"
echo "Keep OFFLINE, never on any server:  ca.key"
echo
echo "KMS server  /etc/kms/kms.env :  KMS_TLS_CLIENT_PINS=$(pin app-client.crt)"
echo "App server  /opt/finomix/.env:  KMS_SERVER_PIN=$(pin kms-server.crt)"
echo
echo "NOTE: the pin is sha256 over the WHOLE DER certificate, not the public key —"
echo "      reissuing a leaf changes the pin even if the keypair is reused."
echo "      KMS_TLS_CLIENT_PINS accepts a comma-separated list; use that to stage a"
echo "      client-cert rotation with no downtime."
echo
echo "Set a calendar reminder: leaves expire in 1 year — reissue and update pins."
