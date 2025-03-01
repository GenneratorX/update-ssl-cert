#!/bin/bash
set -euo pipefail

LOG_PATH='/var/log/cert-renew.log'
TMP_PATH="$PWD/tmp"
CERT_PATH="$PWD/backup"
CONF_PATH="$PWD/config"
VENV_PATH="$PWD/.venv"

PRIVATE_KEY_TYPE='prime256v1'

PRIVATE_KEY_NAME='letsencryptPrivkey.pem'
CERT_KEY_NAME='letsencryptCert.pem'
CHAIN_KEY_NAME='letsencryptChain.pem'
FULLCHAIN_KEY_NAME='letsencryptFullchain.pem'

CERTBOT_NOTIFICATION_EMAIL='fake@email.com'

# Print STDOUT and STDERR to screen and log both to a file
exec > >(tee -a "$LOG_PATH") 2>&1

echo "# Started script execution at $(date --iso-8601=seconds) #"

if [ ! -d "$TMP_PATH" ]; then
        echo "========> Creating temp directory"
        install -m 700 -d "$TMP_PATH"
else
        echo "========> Cleaning temp directory"
        rm -f "$TMP_PATH/*"
fi

if [ ! -d "$CERT_PATH" ]; then
        echo "========> Creating backup certificate directory"
        install -m 700 -d "$CERT_PATH" "$CERT_PATH/cert_file"
fi

if [ ! -f "$VENV_PATH/pyvenv.cfg" ]; then
        echo "========> Creating python virtual env"
        python3 -m venv "$VENV_PATH"
fi

if [ ! -d "$CONF_PATH" ]; then
        echo "========> Creating configuration directory"
        install -m 700 -d "$CONF_PATH" "$CONF_PATH/certbot" "$CONF_PATH/csr_config"
        echo "[ERROR] Please add CSR config files to '$CONF_PATH/csr_config' and 'cloudflare.conf' containing a CloudFlare API key to '$CONF_PATH'"
        exit 1
fi

if [ ! -f "$CONF_PATH/cloudflare.conf" ]; then
        echo "[ERROR] 'cloudflare.conf' not found in '$CONF_PATH'"
        exit 1
fi

if [ ! -f "$CONF_PATH/csr_config/openssl.conf" ]; then
        echo "[ERROR] 'openssl.conf' not found in '$CONF_PATH/csr_config'"
        exit 1
fi

echo "========> Generating private key"
openssl ecparam -genkey -name "$PRIVATE_KEY_TYPE" -check -out "$TMP_PATH/$PRIVATE_KEY_NAME"

echo "========> Verifying private key"
openssl ec -text -noout -check -in "$TMP_PATH/$PRIVATE_KEY_NAME"

echo "========> Generating Certificate Signing Request (CSR)"
openssl req -new -key "$TMP_PATH/$PRIVATE_KEY_NAME" -config "$CONF_PATH/csr_config/openssl.conf" -out "$TMP_PATH/csr" -verify -verbose

echo "========> Verifying CSR"
openssl req -text -noout -verify -in "$TMP_PATH/csr"

# Activate VENV
# shellcheck source=./.venv/bin/activate
. "$VENV_PATH/bin/activate"

echo "========> Updating python dependencies"
pip install -U pip
pip install -r 'requirements.txt'

echo "========> Obtaining SSL certificate from LetsEncrypt using CertBot"
cd "$TMP_PATH"
certbot certonly \
        --config-dir "$CONF_PATH/certbot/config" \
        --work-dir "$CONF_PATH/certbot/work" \
        --logs-dir "$CONF_PATH/certbot/logs" \
        --non-interactive \
        --agree-tos \
        --email "$CERTBOT_NOTIFICATION_EMAIL" \
        --csr 'csr' \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CONF_PATH/cloudflare.conf" \
        --dns-cloudflare-propagation-seconds 30

current_timestamp="$(date +%s)"

echo "========> Renaming certificate files"
echo "0000_cert.pem  -> $CERT_KEY_NAME.$current_timestamp"
mv -f '0000_cert.pem' "$CERT_KEY_NAME.$current_timestamp"
echo "0000_chain.pem -> $CHAIN_KEY_NAME"
mv -f '0000_chain.pem' "$CHAIN_KEY_NAME"
echo "0001_chain.pem -> $FULLCHAIN_KEY_NAME"
mv -f '0001_chain.pem' "$FULLCHAIN_KEY_NAME"

echo "========> Fixing file permissions"
chmod 400 "$CERT_KEY_NAME.$current_timestamp" "$CHAIN_KEY_NAME" "$FULLCHAIN_KEY_NAME" "$PRIVATE_KEY_NAME"

echo "========> Packing certificate files with file name 'letsencrypt.$current_timestamp.tar.xz'"
XZ_OPT=-e9 tar -Jcvf "$CERT_PATH/letsencrypt.$current_timestamp.tar.xz" "$PRIVATE_KEY_NAME" "$CHAIN_KEY_NAME" "$FULLCHAIN_KEY_NAME" --remove-files
chmod 400 "$CERT_PATH/letsencrypt.$current_timestamp.tar.xz"

echo "========> Saving main certificate file with file name '$CERT_KEY_NAME.$current_timestamp'"
mv -n "$CERT_KEY_NAME.$current_timestamp" "$CERT_PATH/cert_file/"

echo "========> Cleaning up"
rm -f ./*

echo "========> Updating TLSA DNS records"
cd ..
./update_tlsa.py --cert_path "$CERT_PATH/cert_file/$CERT_KEY_NAME.$current_timestamp" --h3

# Deactivate VENV
deactivate

echo "# Ended script execution at $(date --iso-8601=seconds) #"
