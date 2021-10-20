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

    return vpc


@pytest.fixture()
def networking(ec2_client, vpc):
    vpc_id = vpc.get('Vpc').get('VpcId')
    subnet = ec2_client.create_subnet(CidrBlock='10.0.0.0/16', VpcId=vpc_id)
    subnet_id = subnet.get('Subnet').get('SubnetId')
    ig = ec2_client.create_internet_gateway()
    ig_id = ig.get('InternetGateway').get('InternetGatewayId')
    ec2_client.attach_internet_gateway(InternetGatewayId=ig_id,
                                       VpcId=vpc.get('Vpc').get('VpcId'))
    route_table = ec2_client.create_route_table(VpcId=vpc_id)
    route_table_id = route_table.get('RouteTable').get('RouteTableId')
    ec2_client.create_route(RouteTableId=route_table_id, DestinationCidrBlock='0.0.0.0/0', GatewayId=ig_id)
    return {
        'vpc': {
            'id': vpc_id,
            'resp': vpc
        },
        'subnet': {
            'id': subnet_id,
            'resp': subnet
        },
        'ig': {
            'id': ig_id,
            'resp': ig
        },
        'route_table': {
            'id': route_table_id,
            'resp': route_table
        }
    }
@pytest.fixture()
def ec2_instance(ec2_client, networking, security_group_with_eni):
    resp = ec2_client.create_instances(
        ImageId='ami-835b4efa',
        InstanceType='t2.micro',
        MaxCount=1,
        MinCount=1,
        NetworkInterfaces=[
            {
                'SubnetId': networking.get('subnet').get('id'),
                'Groups': [security_group_with_eni]
            }
        ]
    )
    return resp


@pytest.fixture()
def s3_private_bucket(s3_client):
    bucket_name = 'dassana-private-bucket'
    s3_client.create_bucket(
        Bucket=bucket_name,
        ACL='private',
    )
    return bucket_name
