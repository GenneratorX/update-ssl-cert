#!/usr/bin/env python
import argparse
import hashlib
import logging
import os
import re
import sys

from concurrent import futures
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from typing import NamedTuple

import CloudFlare
import CloudFlare.exceptions

MAX_PARALLEL_TASKS = 20


def main():
    log = init_logger()
    args = parse_args()

    if args.api_token is None:
        log.critical("--api_token parameter missing and API_TOKEN environment variable is empty")

    if args.cert_path is None:
        log.critical("--cert_path parameter missing and CERT_PATH environment variable is empty")

    log.info("parsing certificate file")
    try:
        cert = parse_cert(args.cert_path)
    except IOError as e:
        log.critical("could not open certificate file. Reason: %s", e.strerror)
    except ValueError as e:
        log.critical("could not parse certificate file. Reason: %s", e)

    log.info("creating CloudFlare API client")
    cf = CloudFlare.CloudFlare(token=args.api_token)

    common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    log.info("getting zone for domain '%s'", common_name)
    try:
        zones = cf.zones.get(params={"name": common_name})
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        log.critical("could not get zone for domain. Reason: %s", e)
    if len(zones) != 1:
        log.critical("could not find zone for domain")
    zone_id: str = zones[0]["id"]

    log.info("getting TLSA DNS records from zone")
    try:
        dns_records = cf.zones.dns_records.get(zone_id, params={"type": "TLSA"})
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        log.critical("could not get DNS records from zone. Reason: %s", e)

    record_ids: list[str] = []
    if args.delete_all:
        for record in dns_records:
            record_ids.append(record["id"])
    else:
        record_ids = filter_dns_records(dns_records, cert)
    log.info("found %d TLSA DNS records (%d will be removed)", len(dns_records), len(record_ids))

    if len(record_ids) != 0:
        delete_errors = delete_dns_records(cf, zone_id, record_ids)
        for record_id in delete_errors:
            log.warning("failed to delete DNS record with ID '%s'. Reason: %s", record_id, delete_errors[record_id])
        log.info("deleted %d/%d TLSA DNS records", len(record_ids) - len(delete_errors), len(record_ids))

    log.info("creating TLSA DNS records for certificate")
    tlsa_records = create_tlsa_records(cert, args.h3)
    create_errors = create_dns_records(cf, zone_id, tlsa_records)
    for record_name in create_errors:
        log.warning("failed to create DNS record with name '%s'. Reason: %s", record_name, create_errors[record_name])
    log.info("created %d/%d TLSA DNS records", len(tlsa_records) - len(create_errors), len(tlsa_records))


def parse_cert(cert_path: str) -> x509.Certificate:
    """
    Parse SSL certificate file

    :param str cert_path: The path of the SSL certificate
    :return: The certificate object
    :rtype: cryptography.x509.Certificate
    :raises IOError: if the certificate file can not be read
    :raises ValueError: if the certificate file is not a valid PEM certificate
    """

    with open(cert_path, "rb") as cert_file:
        cert = cert_file.read()
        return x509.load_pem_x509_certificate(cert)


class TLSA_data(NamedTuple):
    """
    TLSA DNS record data

    :param int usage: The usage of the certificate [0-3]
    :param int selector: The selector of the certificate [0-1]
    :param int matching_type: The matching type of the certificate [0-2]
    :param str certificate: The certificate hash
    """

    usage: int
    selector: int
    matching_type: int
    certificate: str


class TLSA_record(NamedTuple):
    """
    TLSA DNS record

    :param str name: The name of the DNS entry
    :param TLSA_data data: The data of the TLSA record
    :param str type: The type of the DNS entry
    """

    name: str
    data: TLSA_data
    type: str = "TLSA"

    def to_dict(self) -> dict[str, str | dict[str, int | str]]:
        """
        Converts the named tuple to a dictionary

        :return: The object converted to a dictionary
        :rtype: dict[str, str | dict[str, int | str]]
        """

        dictionary = self._asdict()
        dictionary["data"] = self.data._asdict()

        return dictionary


def delete_dns_records(
    cf: CloudFlare.CloudFlare, zone_id: str, record_ids: list[str]
) -> dict[str, CloudFlare.exceptions.CloudFlareAPIError]:
    """
    Bulk delete DNS records

    :param CloudFlare.CloudFlare cf: The cloudflare client object
    :param str zone_id: The zone id to delete DNS records from
    :param list[str] record_ids: The list of DNS record IDs to delete
    :return: The errors encountered during the deletion of the DNS records
    :rtype: dict[str, CloudFlare.exceptions.CloudFlareAPIError]
    """

    delete_errors: dict[str, CloudFlare.exceptions.CloudFlareAPIError] = {}
    with futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL_TASKS) as executor:
        queue = {
            executor.submit(cf.zones.dns_records.delete, zone_id, record_id): record_id for record_id in record_ids
        }
        for future in futures.as_completed(queue):
            record_id = queue[future]
            try:
                future.result()
            except CloudFlare.exceptions.CloudFlareAPIError as e:
                delete_errors[record_id] = e

    return delete_errors


def filter_dns_records(dns_records: list[dict], cert: x509.Certificate) -> list[str]:
    """
    Filter DNS records based on a SSL certificate

    :param list[dict] dns_records: The DNS records
    :param cryptography.x509.Certificate cert: The SSL certificate
    :return: The record IDs of DNS records that match the domain names found in the SSL certificate
    :rtype: list[str]
    """

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    record_ids: list[str] = []

    for record in dns_records:
        record_domain = re.search(r"^(_443|_25)\.(_tcp|_udp)\.(.*)$", record["name"])
        for domain in san:
            if record_domain is not None and record_domain.group(3) == domain:
                record_ids.append(record["id"])
                break

    return record_ids


def create_dns_records(
    cf: CloudFlare.CloudFlare, zone_id: str, dns_records: list[TLSA_record]
) -> dict[str, CloudFlare.exceptions.CloudFlareAPIError]:
    """
    Bulk create DNS records

    :param CloudFlare.CloudFlare cf: The cloudflare client object
    :param str zone_id: The zone id to create DNS records in
    :param list[TLSA_record] dns_records: The DNS records to create
    :return: The errors encountered during the creation of the DNS records
    :rtype: dict[str, CloudFlare.exceptions.CloudFlareAPIError]
    """

    create_errors: dict[str, CloudFlare.exceptions.CloudFlareAPIError] = {}
    with futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL_TASKS) as executor:
        queue = {
            executor.submit(cf.zones.dns_records.post, zone_id, data=dns_record.to_dict()): dns_record
            for dns_record in dns_records
        }
        for future in futures.as_completed(queue):
            record_name = queue[future].name
            try:
                future.result()
            except CloudFlare.exceptions.CloudFlareAPIError as e:
                create_errors[record_name] = e

    return create_errors


def create_tlsa_records(cert: x509.Certificate, h3: bool = False) -> list[TLSA_record]:
    """
    Create TLSA DNS records for a certificate

    :param cryptography.x509.Certificate cert: The SSL certificate
    :param bool h3: Toggles the creation of TLSA DNS entries for HTTP3 clients
    :return: The TLSA DNS records
    :rtype: list[TLSA_record]
    """

    hash = hashlib.sha256(cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)

    tlsa_records: list[TLSA_record] = []
    for domain in san:
        tlsa_records.append(
            TLSA_record(
                name="_443._tcp." + domain, data=TLSA_data(usage=3, selector=1, matching_type=1, certificate=hash)
            )
        )
        if h3:
            tlsa_records.append(
                TLSA_record(
                    name="_443._udp." + domain, data=TLSA_data(usage=3, selector=1, matching_type=1, certificate=hash)
                )
            )

    return tlsa_records


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments

    :return: The command line arguments values
    :rtype: argparse.Namespace
    """

    parser = argparse.ArgumentParser(description="Update TLSA DNS entries")

    parser.add_argument(
        "--api_token",
        default=os.getenv("API_TOKEN"),
        type=str,
        help="CloudFlare API token",
    )
    parser.add_argument(
        "--cert_path",
        default=os.getenv("CERT_PATH"),
        type=str,
        help="SSL certificate path",
    )
    parser.add_argument(
        "--h3",
        default=False,
        help="Enables the creation of TLSA records for HTTP3 clients",
        action="store_true",
    )

    parser.add_argument(
        "--delete_all",
        default=False,
        help="Enables the deletion of all TLSA records found",
        action="store_true",
    )

    args = parser.parse_args()
    return args


class ExitOnErrorHandler(logging.StreamHandler):
    """
    Handler that exits the program when a critical error happens
    """

    def emit(self, record):
        if record.levelno == logging.CRITICAL:
            sys.exit(1)


def init_logger() -> logging.Logger:
    """
    Initialize logger with custom settings

    :return: A custom logger
    :rtype: logging.Logger
    """

    logging.addLevelName(logging.WARNING, "WARN")
    logging.addLevelName(logging.CRITICAL, "CRIT")

    logger = logging.getLogger("update_tlsa")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    logger.addHandler(ExitOnErrorHandler())

    return logger


if __name__ == "__main__":
    main()
