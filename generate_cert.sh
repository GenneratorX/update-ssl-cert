#!/bin/bash
set -eu

LOG_PATH="/var/log/cert-renew.log"

# Print STDOUT and STDERR to screen and log both to a file
exec > >(tee -a "$LOG_PATH") 2>&1

echo "# Started script execution at $(date --iso-8601=seconds) #"

if [ ! -d tmp ]; then
        echo "========> Creating 'tmp' directory"
        mkdir -m 700 tmp
else
        echo "========> Cleaning 'tmp' directory"
        rm -f tmp/*
fi

echo "========> Generating private key"
openssl ecparam -genkey -name prime256v1 -check -out tmp/letsencryptPrivkey.pem

echo "========> Verifying private key"
openssl ec -text -noout -check -in tmp/letsencryptPrivkey.pem

echo "========> Generating Certificate Signing Request (CSR)"
openssl req -new -key tmp/letsencryptPrivkey.pem -config certbot/openssl.conf -out tmp/csr -verify -verbose

echo "========> Verifying CSR"
openssl req -text -noout -verify -in tmp/csr

# Activate VENV
. .venv/bin/activate

echo "========> Obtaining SSL certificate from LetsEncrypt using CertBot"
cd tmp
certbot certonly \
        --config ../certbot/certbot.conf \
        --csr csr \
        --staging \
        --must-staple \
        --staple-ocsp \
        --dns-cloudflare \
        --dns-cloudflare-credentials ../certbot/cloudflare.conf \
        --dns-cloudflare-propagation-seconds 30

current_timestamp=$(date +%s)

echo "========> Renaming certificate files"
echo "0000_cert.pem  -> letsencryptCert.pem.$current_timestamp"
mv -f 0000_cert.pem "letsencryptCert.pem.$current_timestamp"
echo "0000_chain.pem -> letsencryptChain.pem"
mv -f 0000_chain.pem letsencryptChain.pem
echo "0001_chain.pem -> letsencryptFullchain.pem"
mv -f 0001_chain.pem letsencryptFullchain.pem

echo "========> Fixing file permissions"
chmod 400 "letsencryptCert.pem.$current_timestamp" letsencryptChain.pem letsencryptFullchain.pem letsencryptPrivkey.pem

if [ ! -d ../cert ]; then
        echo "========> Creating 'cert' directory"
        mkdir -m 700 ../cert
        mkdir -m 700 ../cert/certificate_file
fi

echo "========> Packing certificate files with file name 'letsencrypt.$current_timestamp.tar.xz'"
XZ_OPT=-e9 tar -Jcvf "../cert/letsencrypt.$current_timestamp.tar.xz" letsencryptPrivkey.pem letsencryptChain.pem letsencryptFullchain.pem --remove-files
chmod 400 "../cert/letsencrypt.$current_timestamp.tar.xz"

echo "========> Saving main certificate file to 'cert/certificate_file' directory with file name 'letsencryptCert.pem.$current_timestamp'"
mv -n "letsencryptCert.pem.$current_timestamp" ../cert/certificate_file/

echo "========> Cleaning up"
rm -f ./*

echo "========> Updating TLSA DNS records"
cd ..
./update_tlsa.py --cert_path "./cert/certificate_file/letsencryptCert.pem.$current_timestamp" --h3

# Deactivate VENV
deactivate

echo "# Ended script execution at $(date --iso-8601=seconds) #"
