# letsencrypt-aws

`letsencrypt-aws` is a program that can be run in the background which
automatically provisions and updates certificates on your AWS infrastructure
using the AWS APIs and [Let's Encrypt](https://letsencrypt.org/).

## How it works

`letsencrypt-aws` takes a list of resources, which can be either ELBs and
which fully-qualified domain names (FQDNs) you want them to be able to serve,
or CloudFront distributions. It runs in a loop and every day does the following:

1. Checks whether the current certificate for the resource is going to
   expire soon (in less than 45 days).

2. Generates a new private key and CSR and sends a request to Let's Encrypt.

3. Takes the DNS challenge from Let's Encrypt and creates a record in Route53
   for that challenge.

4. Completes the Let's Encrypt challenge and receives a certificate.

5. Uploads the new certificate and private key to IAM and updates your
   resource to use the certificate.

In theory all you need to do is make sure this is running somewhere, and your
ELB and CloudFront certificates will be kept minty-fresh.

**WARNING**: `letsencrypt-aws` currently leaves a trail of expired certificates
behind. Until that's fixed, you'll want to have a separate process that goes in
and cleans them up.

## How to run it

Before you can use `letsencrypt-aws` you need to have created an account with
the ACME server (you only need to do this the first time). You can register
using (if you already have an account you can skip this step):

```console
$ # If you're trying to register for a server besides the Let's Encrypt
$ # production one, see the configuration documentation below.
$ python letsencrypt-aws.py register email@host.com
2016-01-09 19:56:19 [acme-register.generate-key]
2016-01-09 19:56:20 [acme-register.register] email=u'email@host.com'
2016-01-09 19:56:21 [acme-register.agree-to-tos]
-----BEGIN RSA PRIVATE KEY-----
[...]
-----END RSA PRIVATE KEY-----
```

You'll need to put the private key somewhere that `letsencrypt-aws` can access
it (either on the local filesystem or in S3).

You will also need to have your AWS credentials configured. You can use any of
the [mechanisms documented by
boto3](https://boto3.readthedocs.org/en/latest/guide/configuration.html), or
use IAM instance profiles (which are supported, but not mentioned by the
`boto3` documentation). See below for which AWS permissions are required.

`letsencrypt-aws` takes its configuration via the `LETSENCRYPT_AWS_CONFIG`
environment variable. The contents of the environment variable should be a JSON
object with the following schema:

```json
{
    "resources": [
        {
            "elb": {
                "name": "ELB name (string)",
                "port": "optional, defaults to 443 (integer)"
            },
            "fqdns": ["list of FQDNs you want in the certificate (strings)"],
            "key_type": "rsa or ecdsa, optional, defaults to rsa (string)"
        },
        {
            "cloudfront": {
                "id": "CloudFront distribution ID (string)",
                "key_type": "rsa, optional, defaults to rsa (string)"
            }
        }
    ],
    "acme_account_key": "location of the account private key (string)",
    "acme_directory_url": "optional, defaults to Let's Encrypt production (string)"
}
```

The `acme_account_key` can either be located on the local filesystem or in S3.
To specify a local file you provide `"file:///path/to/key.pem"`, for S3 provide
`"s3://bucket-name/object-name"`. The key should be a PEM-formatted RSA private
key.

Then you can simply run `python letsencrypt-aws.py update-certificates`.

If you add the `--persistent` flag it will run forever, rather than just once,
sleeping for 24 hours between each check for certificate expiration. This is
useful for production environments.

If your certificate is not expiring soon, but you need to issue a new one
anyway, the `--force-issue` flag can be provided.

If you're into [Docker](https://www.docker.com/), there is an automatically-built
image of `letsencrypt-aws` available as
[`alexgaynor/letsencrypt-aws`](https://hub.docker.com/r/alexgaynor/letsencrypt-aws/).

## CloudFront and ECDSA

[Amazon CloudFront does not currently support ECDSA keys](http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/SecureConnections.html#CNAMEsAndHTTPS):

> *Private Key*
> [...] It must also be an RSA private key in PEM format, where the PEM header is
> `BEGIN RSA PRIVATE KEY` and the footer is `END RSA PRIVATE KEY`. [...]

## Operational Security

Keeping the source of your certificates secure is, for obvious reasons,
important. `letsencrypt-aws` relies heavily on the AWS APIs to do its
business, so we recommend running this code from EC2, so that you can use the
Metadata service for managing credentials. You can give your EC2 instance an
IAM instance profile with permissions to manage the relevant services (see
below for complete details).

You need to make sure that the ACME account private key is kept secure. The
best choice is probably in an S3 bucket with encryption enabled and access
limited with IAM.

Finally, wherever you're running `letsencrypt-aws` needs to be trusted.
`letsencrypt-aws` generates private keys in memory and uploads them to IAM
immediately, they are never stored on disk.

### IAM Policy

The minimum set of permissions needed for `letsencrypt-aws` to work is:

* `route53:ChangeResourceRecordSets`
* `route53:GetChange`
* `route53:ListHostedZones`
* `iam:ListServerCertificates`
* `iam:UploadServerCertificate`

plus (for ELBs):
* `elasticloadbalancing:DescribeLoadBalancers`
* `elasticloadbalancing:SetLoadBalancerListenerSSLCertificate`

and / or (for CloudFront distributions):
* `cloudfront:GetDistributionConfig`
* `cloudfront:UpdateDistribution`

If your `acme_account_key` is provided as an `s3://` URI you will also need:

* `s3:GetObject`

#### Sample IAM Policy

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets",
                "route53:GetChange",
                "route53:GetChangeDetails",
                "route53:ListHostedZones"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:SetLoadBalancerListenerSSLCertificate"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "cloudfront:GetDistributionConfig",
                "cloudfront:UpdateDistribution"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "iam:ListServerCertificates",
                "iam:UploadServerCertificate"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

You can of course restrict these permissions further using the magic of IAM;
this is left as an exercise to the reader.
