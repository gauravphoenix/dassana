from typing import Dict
from dassana.common.aws_client import LambdaTestContext
import pytest

SUBNET = 'subnet'
GROUP_ID = 'GroupId'
VPC = 'vpc'
ID = 'id'

@pytest.fixture()
def group_name():
    return 'udyr'


@pytest.fixture()
def security_group_without_eni(ec2_client, networking, group_name):
    resp = ec2_client.create_security_group(
        VpcId=networking.get(VPC).get(ID),
        GroupName=group_name,
        Description='Security group for testing %s' % __file__
    )
    group_id = resp.get(GROUP_ID)
    return group_id


@pytest.fixture()
def eni(ec2_client, networking, security_group_with_eni):
    resp = ec2_client.create_network_interface(
        SubnetId=networking.get(SUBNET).get(ID),
        Groups=[security_group_with_eni],
        Description='ENI for testing %s' % __file__,
        PrivateIpAddress='10.0.2.17'
    )
    return resp.get('NetworkInterface').get('NetworkInterfaceId')


@pytest.fixture()
def security_group_with_eni(ec2_client, networking, group_name):
    resp = ec2_client.create_security_group(
        VpcId=networking.get(VPC).get(ID),
        GroupName=group_name,
        Description='Security group for testing %s' % __file__
    )
    group_id = resp.get(GROUP_ID)
    return group_id


def test_handle_security_group_without_eni(security_group_without_eni, region):
    from handler_what_enis_are_attached_to_sg import handle
    result: Dict = handle({'groupId': security_group_without_eni, 'region': region}, LambdaTestContext('leblanc',
                                                                                                       env={},
                                                                                                       custom={}))
    assert len(result.get('result')) == 0


def test_handle_security_group_with_eni(security_group_with_eni, region, eni):
    from handler_what_enis_are_attached_to_sg import handle
    result: Dict = handle({'groupId': security_group_with_eni, 'region': region}, LambdaTestContext('tf',
                                                                                                    env={},
                                                                                                    custom={}))
    assert len(result.get('result')) == 1
    assert result.get('result')[0].get('NetworkInterfaceId') == eni
