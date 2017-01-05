"""
letsencrypt-aws provisions and updates certificates in your AWS infrastructure.
"""

import datetime
import json
import os
import sys
import time

import click

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from botocore.exceptions import WaiterError

import boto3

import OpenSSL.crypto

import rfc3986

import acme.challenges
import acme.client
import acme.jose

DEFAULT_ACME_DIRECTORY_URL = "https://acme-v01.api.letsencrypt.org/directory"

DEFAULT_CERTIFICATE_EXPIRATION_THRESHOLD = datetime.timedelta(days=45)

PERSISTENT_SLEEP_INTERVAL = 60 * 60 * 24 # seconds, one day

DNS_TTL = 30 # seconds


class Logger(object):
    """Simple logging class that writes to stdout."""
    # pylint: disable=too-few-public-methods

    def __init__(self):
        self._out = sys.stdout

    def emit(self, event, **data):
        """Write a single log record."""

        formatted_data = " ".join(
            "{}={!r}".format(k, v) for k, v in data.iteritems()
        )
        self._out.write("{} [{}] {}\n".format(
            datetime.datetime.utcnow().replace(microsecond=0),
            event,
            formatted_data
        ))


def generate_rsa_private_key():
    """Generate a new 2048-bit RSA key using the default backend."""
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def generate_ecdsa_private_key():
    """Generate a new ECDSA key using the default backend and the NIST P-256r1 curve."""
    return ec.generate_private_key(ec.SECP256R1(), backend=default_backend())


def generate_csr(private_key, fqdns):
    """
    Generate a new certificate signing request signed with the provided private key.

    Uses fqdns[0] as the Subject of the generated CSR; all elements of fqdns
    will be included as DNSName entries in the SubjectAlternativeName.

    Uses SHA-256 to generate the certificate hash.
    """

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        # This is the same thing the official letsencrypt client does.
        x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, fqdns[0]),
        ])
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(fqdn)
            for fqdn in fqdns
        ]),
        # TODO: change to `critical=True` when Let's Encrypt supports it.
        critical=False,
    )
    return csr_builder.sign(private_key, hashes.SHA256(), default_backend())


def find_dns_challenge(authz):
    """Yield DNS01 challenges in the ACME authorization challenge."""
    for combo in authz.body.resolved_combinations:
        if (
                len(combo) == 1
                and isinstance(combo[0].chall, acme.challenges.DNS01)
        ):
            yield combo[0]


def get_zone_id_for_domain(route53_client, domain):
    """Get the Route53 zone ID for the provided domain."""
    for page in route53_client.get_paginator("list_hosted_zones").paginate():
        for zone in page["HostedZones"]:
            # This assumes that zones are returned sorted by specificity,
            # meaning in the following order:
            # ["foo.bar.baz.com", "bar.baz.com", "baz.com", "com"]
            if (
                    domain.endswith(zone["Name"]) or
                    (domain + ".").endswith(zone["Name"])
            ):
                return zone["Id"]


def wait_for_route53_change(route53_client, change_id):
    """
    Wait for a Route53 record change to complete.

    Polls Route53.Client.get_change() every 5 seconds until the status
    is INSYNC.

    Raises WaiterError if it hasn't completed after 24 retries (2min).

    boto3 provides a Route53 waiter for exactly this purpose, but it
    polls every 30s for 60 times, which is neither timely nor helpful
    for our use case.
    """

    retries = 0
    while True:
        response = route53_client.get_change(Id=change_id)
        if response["ChangeInfo"]["Status"] == "INSYNC":
            return

        if retries < 24:
            time.sleep(5)
            retries = retries + 1
        else:
            raise WaiterError(
                name='resource_record_sets_changed',
                reason='Max attempts exceeded.'
            )


def change_txt_record(route53_client, action, zone_id, name, value):
    """Change (create, add, delete) a TXT record."""
    response = route53_client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": name,
                        "Type": "TXT",
                        "TTL": DNS_TTL,
                        "ResourceRecords": [
                            # For some reason TXT records need to be manually
                            # quoted.
                            {"Value": '"{}"'.format(value)}
                        ],
                    }
                }
            ]
        }
    )
    return response["ChangeInfo"]["Id"]


def generate_certificate_name(fqdns, cert):
    """
    Generate a probably-unique certificate name.

    The certificate name won't be particularly useful in the AWS console,
    as it's going to start with the serial number and expiration date,
    but we're assigning the certificate to the resource programmatically
    so we don't care so much about that.

    Truncates to the 128-character limit on AWS IAM server certificate names.
    """
    return "{serial}-{expiration}-{fqdns}".format(
        serial=cert.serial,
        expiration=cert.not_valid_after.date(),
        fqdns="-".join(f.replace(".", "_") for f in fqdns),
    )[:128]


def get_load_balancer_certificate(elb_client, elb_name, elb_port):
    """Get the load balancer's certificate ID."""
    response = elb_client.describe_load_balancers(
        LoadBalancerNames=[elb_name]
    )
    [description] = response["LoadBalancerDescriptions"]
    [certificate_id] = [
        listener["Listener"]["SSLCertificateId"]
        for listener in description["ListenerDescriptions"]
        if listener["Listener"]["LoadBalancerPort"] == elb_port
    ]
    return certificate_id


def get_cloudfront_certificate(cloudfront_client, cloudfront_id):
    """
    Get the CloudFront distribution's IAM server certificate ID.

    Will return None if the distribution is not using an IAM server
    certificate.
    """
    return cloudfront_client.get_distribution_config(
        Id=cloudfront_id
    )[u'DistributionConfig'][u'ViewerCertificate'].get(u'IAMCertificateId')


def find_certificate(iam_client, ssl_certificate_id_or_arn):
    """
    Find a certificate in the list of IAM server certificates.

    Strangely, IAM doesn't provide a way to look up a certificate by its ID or ARN.
    """
    paginator = iam_client.get_paginator("list_server_certificates").paginate()
    for page in paginator:
        for server_certificate in page["ServerCertificateMetadataList"]:
            if (
                    server_certificate["Arn"] == ssl_certificate_id_or_arn
                    or server_certificate["ServerCertificateId"] == ssl_certificate_id_or_arn
            ):
                yield server_certificate


def get_certificate_expiration(logger, iam_client, ssl_certificate_arn):
    """
    Get the certificate expiration date from IAM server certificate metadata.
    """
    logger.emit("get-certificate-expiration", arn=ssl_certificate_arn)

    return find_certificate(
        iam_client, ssl_certificate_arn
    ).next()["Expiration"].date()


class AuthorizationRecord(object):
    """Data object to hold authorization details."""
    # pylint: disable=too-few-public-methods

    def __init__(self, fqdn, authz, dns_challenge, route53_change_id,
                 route53_zone_id):
        self.fqdn = fqdn
        self.authz = authz
        self.dns_challenge = dns_challenge
        self.route53_change_id = route53_change_id
        self.route53_zone_id = route53_zone_id


def start_dns_challenge(logger, acme_client, route53_client, fqdn):
    """
    Start the ACME DNS challenge process.

    Requests the challenge, computes the response, and requests
    creation of the TXT record containing the response.
    """

    logger.emit("request-acme-challenge", fqdn=fqdn)
    authz = acme_client.request_domain_challenges(
        fqdn, new_authzr_uri=acme_client.directory.new_authz
    )

    [dns_challenge] = find_dns_challenge(authz)

    zone_id = get_zone_id_for_domain(route53_client, fqdn)
    logger.emit("create-txt-record", fqdn=fqdn)
    change_id = change_txt_record(
        route53_client,
        "CREATE",
        zone_id,
        dns_challenge.validation_domain_name(fqdn),
        dns_challenge.validation(acme_client.key),
    )

    return AuthorizationRecord(
        fqdn,
        authz,
        dns_challenge,
        change_id,
        zone_id,
    )


def complete_dns_challenge(logger, acme_client, route53_client, authz_record):
    """
    Completes the ACME DNS challenge process.

    Waits for the TXT record to be created, then tells Let's Encrypt
    to confirm the challenge response.
    """
    logger.emit("wait-for-route53", fqdn=authz_record.fqdn)
    wait_for_route53_change(route53_client, authz_record.route53_change_id)

    response = authz_record.dns_challenge.response(acme_client.key)

    logger.emit("local-validation", fqdn=authz_record.fqdn)
    verified = response.simple_verify(
        authz_record.dns_challenge.chall,
        authz_record.fqdn,
        acme_client.key.public_key()
    )
    if not verified:
        raise ValueError("Failed verification")

    logger.emit("answer-challenge", fqdn=authz_record.fqdn)
    acme_client.answer_challenge(authz_record.dns_challenge, response)


def request_certificate(logger, acme_client, authorizations, csr):
    """Request the certificate after challenge/response completes."""
    logger.emit("request-cert")
    cert_response, _ = acme_client.poll_and_request_issuance(
        acme.jose.util.ComparableX509(
            OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_ASN1,
                csr.public_bytes(serialization.Encoding.DER),
            )
        ),
        authzrs=[authz_record.authz for authz_record in authorizations],
    )
    pem_certificate = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM, cert_response.body
    )
    pem_certificate_chain = "\n".join(
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        for cert in acme_client.fetch_chain(cert_response)
    )
    return pem_certificate, pem_certificate_chain


def upload_certificate(logger, iam_client, fqdns, iam_cert_path, private_key,
                       pem_certificate, pem_certificate_chain):
    """Upload the private key, certificate, and chain to IAM."""
    logger.emit("upload-iam-certificate.start")
    response = iam_client.upload_server_certificate(
        ServerCertificateName=generate_certificate_name(
            fqdns,
            x509.load_pem_x509_certificate(pem_certificate, default_backend())
        ),
        Path=iam_cert_path,
        PrivateKey=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        CertificateBody=pem_certificate,
        CertificateChain=pem_certificate_chain,
    )
    arn = response["ServerCertificateMetadata"]["Arn"]
    name = response["ServerCertificateMetadata"]["ServerCertificateName"]

    logger.emit("upload-iam-certificate.uploaded", arn=arn, name=name)
    ret = response["ServerCertificateMetadata"]

    retries = 0
    while retries < 10:
        logger.emit('checking that the certificate is available')

        cert_metadata = iam_client.list_server_certificates()
        cert_arns = [c['Arn'] for c in cert_metadata['ServerCertificateMetadataList']]
        if ret['Arn'] in cert_arns:
            break
        else:
            time.sleep(5)
            retries = retries + 1

    return ret


def add_certificate_to_elb(logger, elb_client, elb_name, elb_port, new_cert_arn):
    """Configure the certificate on the ELB."""
    logger.emit("update-elb.set-elb-certificate", elb_name=elb_name)
    elb_client.set_load_balancer_listener_ssl_certificate(
        LoadBalancerName=elb_name,
        SSLCertificateId=new_cert_arn,
        LoadBalancerPort=elb_port,
    )


def add_certificate_to_cloudfront(logger, cloudfront_client, cloudfront_id, new_cert_id):
    """Configure the certificate on the CloudFront distribution."""
    logger.emit("update-cloudfront.get-distribution-config", cloudfront_id=cloudfront_id)

    # I would occasionally get OpenSSL.SSL.SysCallError thrown when interacting
    # with CloudFront, but strangely ONLY with CloudFront. boto3 has retry logic
    # built in, but it doesn't seem to catch this particular problem.
    retries = 0
    while True:
        try:
            response = cloudfront_client.get_distribution_config(Id=cloudfront_id)
            config = response[u'DistributionConfig']
            break
        except OpenSSL.SSL.SysCallError:
            logger.emit("retrying")
            retries = retries + 1
            if retries > 3: # 3 is an arbitrary number.
                raise

    config[u'ViewerCertificate'][u'IAMCertificateId'] = new_cert_id

    # These are deprecated, setting them anyway
    config[u'ViewerCertificate'][u'Certificate'] = new_cert_id
    config[u'ViewerCertificate'][u'CertificateSource'] = 'iam'

    if u'CloudFrontDefaultCertificate' in config[u'ViewerCertificate']:
        del config[u'ViewerCertificate'][u'CloudFrontDefaultCertificate']

    if u'ACMCertificateArn' in config[u'ViewerCertificate']:
        del config[u'ViewerCertificate'][u'ACMCertificateArn']

    # http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesMinimumSSLProtocolVersion
    # If you selected Custom SSL Certificate and you selected Only Clients that
    # Support Server Name Indication (SNI), CloudFront uses TLSv1, which is the
    # minimum allowed SSL protocol for SNI
    if 'SSLSupportMethod' not in config['ViewerCertificate']:
        config['ViewerCertificate']['SSLSupportMethod'] = 'sni-only'
        config['ViewerCertificate']['MinimumProtocolVersion'] = 'TLSv1'

    config[u'ViewerCertificate'][u'IAMCertificateId'] = new_cert_id

    logger.emit("update-cloudfront.update-distribution", cloudfront_id=cloudfront_id)

    # I would occasionally get OpenSSL.SSL.SysCallError thrown when interacting
    # with CloudFront, but strangely ONLY with CloudFront. boto3 has retry logic
    # built in, but it doesn't seem to catch this particular problem.
    retries = 0
    while True:
        try:
            cloudfront_client.update_distribution(
                Id=cloudfront_id,
                DistributionConfig=config,
                IfMatch=response[u'ETag']
            )
            break
        except OpenSSL.SSL.SysCallError:
            logger.emit("retrying")
            retries = retries + 1
            if retries > 3:
                raise


def generate_certificate(logger, acme_client, boto3_session, fqdns, key_type):
    """Generate a certificate using ACME DNS challenge and Route53."""
    route53_client = boto3_session.client("route53")

    if key_type == "rsa":
        private_key = generate_rsa_private_key()
    elif key_type == "ecdsa":
        private_key = generate_ecdsa_private_key()
    else:
        raise ValueError("Invalid key_type: {!r}".format(key_type))

    csr = generate_csr(private_key, fqdns)

    authorizations = []
    try:
        for fqdn in fqdns:
            authz_record = start_dns_challenge(
                logger, acme_client, route53_client, fqdn
            )
            authorizations.append(authz_record)

        for authz_record in authorizations:
            complete_dns_challenge(
                logger, acme_client, route53_client, authz_record
            )

        pem_certificate, pem_certificate_chain = request_certificate(
            logger, acme_client, authorizations, csr
        )

        return private_key, pem_certificate, pem_certificate_chain

    finally:
        for authz_record in authorizations:
            logger.emit("delete-txt-record", fqdn=authz_record.fqdn)
            dns_challenge = authz_record.dns_challenge
            change_txt_record(
                route53_client,
                "DELETE",
                authz_record.route53_zone_id,
                dns_challenge.validation_domain_name(authz_record.fqdn),
                dns_challenge.validation(acme_client.key),
            )


def update(logger, acme_client, boto3_session,
           get_certificate_id_fn, update_certificate_fn,
           force_issue, fqdns, key_type, iam_cert_path):
    """
    Update a resource with a new certificate if needed or forced.

    Checks if the current certificate is about to expire, and if so
    uses ACME and Route53 to negotiate the challenge-response and
    certificate generation process with Let's Encrypt. Once we have
    a new certificate, uploads it to IAM and then updates the resource
    to use the new certificate.

    Uses the provided methods to get the current certificate ID for the
    resource and then to update the resource to use the new certificate.
    """
    certificate_id = get_certificate_id_fn()

    iam_client = boto3_session.client("iam")

    if certificate_id is not None:
        expiration_date = get_certificate_expiration(
            logger, iam_client, certificate_id
        )

        logger.emit("certificate-expiration", expiration_date=expiration_date)

        days_until_expiration = expiration_date - datetime.date.today()
        if (
                days_until_expiration > DEFAULT_CERTIFICATE_EXPIRATION_THRESHOLD
                and not force_issue
        ):
            return

    private_key, pem_certificate, pem_certificate_chain = generate_certificate(
        logger, acme_client, boto3_session, fqdns, key_type
    )

    new_cert_metadata = upload_certificate(
        logger, iam_client, fqdns, iam_cert_path,
        private_key, pem_certificate, pem_certificate_chain
    )

    # Sleep before trying to set the certificate, it appears to sometimes fail
    # without this.
    logger.emit('sleeping just a bit longer')
    time.sleep(15)

    update_certificate_fn(new_cert_metadata)


def update_elb(logger, acme_client, boto3_session,
               force_issue, elb_name, elb_port, fqdns, key_type):
    """Update the certificate on an ELB (if necessary or forced)."""
    logger.emit("update-elb.start", elb_name=elb_name)

    elb_client = boto3_session.client("elb")

    def get_certificate_id():
        """Get the current certificate used by this ELB."""
        return get_load_balancer_certificate(
            elb_client, elb_name, elb_port
        )

    def update_certificate(new_cert_metadata):
        """Update the ELB to use the certificate."""
        add_certificate_to_elb(
            logger, elb_client, elb_name, elb_port, new_cert_metadata['Arn']
        )

    update(logger, acme_client, boto3_session,
           get_certificate_id, update_certificate,
           force_issue, fqdns, key_type, '/')

    logger.emit("update-elb.done", elb_name=elb_name)


def update_cloudfront(logger, acme_client, boto3_session, force_issue,
                      cloudfront_id, key_type):
    """Update the certificate on a CloudFront distribution (if necessary or forced)."""
    logger.emit("update-cloudfront.start", cloudfront_id=cloudfront_id)

    cloudfront_client = boto3_session.client("cloudfront")

    config = cloudfront_client.get_distribution_config(
        Id=cloudfront_id
    )[u'DistributionConfig']

    certificate_id = config[u'ViewerCertificate'].get(u'IAMCertificateId')

    fqdns = [unicode(i) for i in config[u'Aliases'][u'Items']]

    def get_certificate_id():
        """Get the current certificate used by this CloudFront distribution."""
        return certificate_id

    def update_certificate(new_cert_metadata):
        """Update the CloudFront distribution to use the certificate."""
        add_certificate_to_cloudfront(
            logger,
            cloudfront_client,
            cloudfront_id,
            new_cert_metadata['ServerCertificateId'],
        )

    update(logger, acme_client, boto3_session,
           get_certificate_id, update_certificate,
           force_issue, fqdns, key_type,
           '/cloudfront/letsencrypt-aws/{:s}/'.format(cloudfront_id))

    logger.emit("update-cloudfront.done", cloudfront_id=cloudfront_id)


def update_resources(logger, acme_client, boto3_session, force_issue, resources):
    """Update the configured set of ELBs and CloudFront distributions."""
    logger.emit("update-resources.start")

    for resource in resources:
        if 'elb' in resource:
            update_elb(
                logger,
                acme_client,
                boto3_session,
                force_issue,
                resource["elb"]["name"],
                resource["elb"].get("port", 443),
                resource["fqdns"],
                resource.get("key_type", "rsa")
            )

        if 'cloudfront' in resource:
            update_cloudfront(
                logger,
                acme_client,
                boto3_session,
                force_issue,
                resource["cloudfront"]["id"],
                resource["cloudfront"].get("key_type", "rsa")
            )

    logger.emit("update-resources.done")


def setup_acme_client(boto3_session, acme_directory_url, acme_account_key_url):
    """
    Sets up an ACME client with the provided URL and private key URL.

    Reads the private key located at a file: or s3: URL.
    """

    uri = rfc3986.urlparse(acme_account_key_url)
    if uri.scheme == "file":
        with open(uri.path) as f:
            key = f.read()
    elif uri.scheme == "s3":
        s3_client = boto3_session.client("s3")
        # uri.path includes a leading "/"
        response = s3_client.get_object(Bucket=uri.host, Key=uri.path[1:])
        key = response["Body"].read()
    else:
        raise ValueError(
            "Invalid acme account key: {!r}".format(acme_account_key_url)
        )

    key = serialization.load_pem_private_key(
        key, password=None, backend=default_backend()
    )
    return acme_client_for_private_key(acme_directory_url, key)


def acme_client_for_private_key(acme_directory_url, private_key):
    """Creates an ACME client with the provided URL and private key."""
    return acme.client.Client(
        # TODO: support EC keys, when acme.jose does.
        acme_directory_url, key=acme.jose.JWKRSA(key=private_key)
    )


@click.group()
def cli():
    """Handle command-line invocation."""
    pass


@cli.command(name="update-certificates")
@click.option(
    "--persistent", is_flag=True, help="Runs in a loop, instead of just once."
)
@click.option(
    "--force-issue", is_flag=True, help=(
        "Issue a new certificate, even if the old one isn't close to "
        "expiration."
    )
)
def update_certificates(persistent=False, force_issue=False):
    """Update certificates for the requested resources."""
    logger = Logger()
    logger.emit("startup")

    if persistent and force_issue:
        raise ValueError("Can't specify both --persistent and --force-issue")

    boto3_session = boto3.Session()

    # Structure: {
    #     "resources": [
    #         {"elb": { "name": "...", "port": 443},
    #          "fqdns": ["..."]
    #           "key_type": "rsa|ecdsa" // optional, default = rsa
    #         },
    #         {"cloudfront": {
    #           "id": "<id>",
    #           "key_type": "rsa" // optional, default = rsa
    #         } }
    #     ],
    #     "acme_account_key": "s3://bucket/object",
    #     "acme_directory_url": "(optional)"
    # }
    config = json.loads(os.environ["LETSENCRYPT_AWS_CONFIG"])
    resources = config["resources"]
    acme_directory_url = config.get(
        "acme_directory_url", DEFAULT_ACME_DIRECTORY_URL
    )
    acme_account_key_url = config["acme_account_key"]
    acme_client = setup_acme_client(
        boto3_session, acme_directory_url, acme_account_key_url
    )

    if persistent:
        logger.emit("running", mode="persistent")
        while True:
            update_resources(
                logger, acme_client, boto3_session,
                force_issue, resources
            )
            # Sleep before we check again
            logger.emit("sleeping", duration=PERSISTENT_SLEEP_INTERVAL)
            time.sleep(PERSISTENT_SLEEP_INTERVAL)
    else:
        logger.emit("running", mode="single")
        update_resources(
            logger, acme_client, boto3_session,
            force_issue, resources
        )


@cli.command()
@click.argument("email")
@click.option(
    "--out",
    type=click.File("w"),
    default="-",
    help="Where to write the private key to. Defaults to stdout."
)
def register(email, out):
    """Creates a new private key and registers it with Let's Encrypt."""
    logger = Logger()
    config = json.loads(os.environ.get("LETSENCRYPT_AWS_CONFIG", "{}"))
    acme_directory_url = config.get(
        "acme_directory_url", DEFAULT_ACME_DIRECTORY_URL
    )

    logger.emit("acme-register.generate-key")
    private_key = generate_rsa_private_key()
    acme_client = acme_client_for_private_key(acme_directory_url, private_key)

    logger.emit("acme-register.register", email=email)
    registration = acme_client.register(
        acme.messages.NewRegistration.from_data(email=email)
    )
    logger.emit("acme-register.agree-to-tos")
    acme_client.agree_to_tos(registration)
    out.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    logger.emit("acme-register.done")


if __name__ == "__main__":
    cli()
