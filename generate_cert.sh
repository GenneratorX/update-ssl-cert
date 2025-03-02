#!/bin/bash
set -euo pipefail

LOG_PATH='/var/log/cert-renew.log'

WORK_PATH="$PWD"
TMP_PATH="$PWD/tmp"
CERT_PATH="$PWD/backup"
CONF_PATH="$PWD/config"
VENV_PATH="$PWD/.venv"
CSR_CONF_PATH="$CONF_PATH/csr_config"

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
        install -m 700 -d "$CONF_PATH" "$CONF_PATH/certbot" "$CSR_CONF_PATH"
        echo "[ERROR] Please add CSR config files to '$CSR_CONF_PATH' and 'cloudflare.conf' containing a CloudFlare API key to '$CONF_PATH'"
        exit 1
fi

if [ ! -f "$CONF_PATH/cloudflare.conf" ]; then
        echo "[ERROR] 'cloudflare.conf' not found in '$CONF_PATH'"
        exit 1
fi

generate_cert() {
        if [ -z "$1" ]; then
                echo "[ERROR] No CSR config file specified."
                exit 1
        fi

        echo "========> Generating private key"
        openssl ecparam -genkey -name "$PRIVATE_KEY_TYPE" -check -out "$TMP_PATH/$PRIVATE_KEY_NAME"

        echo "========> Verifying private key"
        openssl ec -text -noout -check -in "$TMP_PATH/$PRIVATE_KEY_NAME"

        echo "========> Generating Certificate Signing Request (CSR)"
        openssl req -new -key "$TMP_PATH/$PRIVATE_KEY_NAME" -config "$1" -out "$TMP_PATH/csr" -verify -verbose

        echo "========> Verifying CSR"
        openssl req -text -noout -verify -in "$TMP_PATH/csr"

        echo "========> Obtaining SSL certificate from LetsEncrypt using CertBot"
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

        cert_name="$(basename "$1" '.conf')"

        echo "========> Packing certificate files with file name '$cert_name.$current_timestamp.tar.xz'"
        XZ_OPT=-e9 tar -Jcvf "$CERT_PATH/$cert_name.$current_timestamp.tar.xz" "$PRIVATE_KEY_NAME" "$CHAIN_KEY_NAME" "$FULLCHAIN_KEY_NAME" --remove-files
        chmod 400 "$CERT_PATH/$cert_name.$current_timestamp.tar.xz"

        echo "========> Saving main certificate file with file name '$cert_name.pem.$current_timestamp'"
        mv -f "$CERT_KEY_NAME.$current_timestamp" "$CERT_PATH/cert_file/$cert_name.pem.$current_timestamp"
        cert_list+=("$CERT_PATH/cert_file/$cert_name.pem.$current_timestamp")

        echo "========> Cleaning up"
        rm -f ./*
}

update_tlsa() {
        if [ -z "$1" ]; then
                echo "[ERROR] No certificate file specified."
                exit 1
        fi

        "$WORK_PATH/update_tlsa.py" --cert_path "$1" --h3
}

# Activate VENV
# shellcheck source=./.venv/bin/activate
. "$VENV_PATH/bin/activate"

echo "========> Updating python dependencies"
pip install -U pip
pip install -r 'requirements.txt'

cd "$TMP_PATH"
cert_list=()
for file in "$CSR_CONF_PATH"/*.conf; do
        if [ -f "$file" ]; then
                echo "========> Found CSR config file: '$file'"
                generate_cert "$file"
        fi
done

for cert in "${cert_list[@]}"; do
        echo "========> Updating TLSA entries for certificate: '$cert'"
        update_tlsa "$cert"
done

# Deactivate VENV
deactivate

echo "# Ended script execution at $(date --iso-8601=seconds) #"
