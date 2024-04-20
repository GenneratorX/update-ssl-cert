#!/bin/bash
set -eu

LOG_PATH="/var/log/cert-renew.log"

# Print STDOUT and STDERR to screen and log both to a file
exec > >(tee -a ${LOG_PATH}) 2>&1

printf "# Started script execution at $(date --iso-8601=seconds) #"

if [ ! -d tmp ]; then
        printf "\n========> Creating 'tmp' directory\n"
        mkdir -m 700 tmp
else
        printf "\n========> Cleaning 'tmp' directory\n"
        rm -f tmp/*
fi

printf "\n========> Generating private key\n"
openssl ecparam -genkey -name prime256v1 -check -out tmp/letsencryptPrivkey.pem

printf "\n========> Verifying private key\n"
openssl ec -text -noout -check -in tmp/letsencryptPrivkey.pem

printf "\n========> Generating Certificate Signing Request (CSR)\n"
openssl req -new -key tmp/letsencryptPrivkey.pem -config certbot/openssl.conf -out tmp/csr -verify -verbose

printf "\n========> Verifying CSR\n"
openssl req -text -noout -verify -in tmp/csr

# Activate VENV
. .venv/bin/activate

printf "\n========> Obtaining SSL certificate from LetsEncrypt using CertBot\n"
cd tmp
certbot certonly --config ../certbot/certbot.conf \
                 --csr csr \
                 --must-staple \
                 --staple-ocsp \
                 --dns-cloudflare \
                 --dns-cloudflare-credentials ../certbot/cloudflare.conf \
                 --dns-cloudflare-propagation-seconds 30

# Deactivate VENV
deactivate

current_timestamp=$(date +%s)

printf "\n========> Renaming certificate files\n"
printf " 0000_cert.pem  -> letsencryptCert.pem.$current_timestamp\n"
mv -f 0000_cert.pem letsencryptCert.pem.$current_timestamp
printf " 0000_chain.pem -> letsencryptChain.pem\n"
mv -f 0000_chain.pem letsencryptChain.pem
printf " 0001_chain.pem -> letsencryptFullchain.pem\n"
mv -f 0001_chain.pem letsencryptFullchain.pem

printf "\n========> Fixing file permissions\n"
chmod 400 letsencryptCert.pem.$current_timestamp letsencryptChain.pem letsencryptFullchain.pem letsencryptPrivkey.pem

if [ ! -d ../cert ]; then
        printf "\n========> Creating 'cert' directory\n"
        mkdir -m 700 ../cert
        mkdir -m 700 ../cert/certificate_file
fi

printf "\n========> Packing certificate files with file name 'letsencrypt.$current_timestamp.tar.xz'\n"
XZ_OPT=-e9 tar -Jcvf ../cert/letsencrypt.$current_timestamp.tar.xz letsencryptPrivkey.pem letsencryptChain.pem letsencryptFullchain.pem --remove-files
chmod 400 ../cert/letsencrypt.$current_timestamp.tar.xz

printf "\n========> Saving main certificate file to 'cert/certificate_file' directory with file name 'letsencryptCert.pem.$current_timestamp'\n"
mv -n letsencryptCert.pem.$current_timestamp ../cert/certificate_file/

printf "\n========> Cleaning up\n"
rm -f *

printf "# Ended script execution at $(date --iso-8601=seconds) #\n"
