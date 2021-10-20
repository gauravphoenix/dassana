import os

import boto3
import pytest
from moto import mock_s3, mock_ec2


@pytest.fixture()
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"


@pytest.fixture()
def region():
    return 'us-east-1'


@pytest.fixture()
def s3_client(aws_credentials, region):
    with mock_s3():
        yield boto3.client('s3', region_name=region)


@pytest.fixture()
def ec2_client(aws_credentials, region):
    with mock_ec2():
        yield boto3.client('ec2', region_name=region)


@pytest.fixture()
def s3_public_bucket_with_website(s3_client):
    bucket_name = 'dassana-public-bucket'
    s3_client.create_bucket(
        Bucket=bucket_name,
        ACL='public-read-write',
    )

    s3_client.put_bucket_website(Bucket='dassana-public-bucket', WebsiteConfiguration={
        'ErrorDocument': {'Key': 'error.html'},
        'IndexDocument': {'Suffix': 'index.html'},
    })
    return bucket_name


@pytest.fixture()
def vpc(ec2_client):
    vpc = ec2_client.create_vpc(
        CidrBlock='10.0.0.0/16',
    )
    return vpc.get('Vpc').get('VpcId')


@pytest.fixture()
def s3_private_bucket(s3_client):
    bucket_name = 'dassana-private-bucket'
    s3_client.create_bucket(
        Bucket=bucket_name,
        ACL='private',
    )
    return bucket_name
