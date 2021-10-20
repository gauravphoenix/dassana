from typing import Dict
from dassana.common.aws_client import LambdaTestContext
import pytest


@pytest.fixture()
def group_name():
    return 'udyr'


@pytest.fixture()
def security_group_with_eni(ec2_client, vpc, group_name):
    resp = ec2_client.create_security_group(
        VpcId=vpc,
        GroupName=group_name,
        Description='Security group for testing %s' % __file__
    )

    return resp.get('GroupId')


def test_handle_security_group_without_eni(security_group_with_eni, region):
    from handler_what_enis_are_attached_to_sg import handle
    result: Dict = handle({'groupId': security_group_with_eni, 'region': region}, LambdaTestContext('leblanc', env={},
                                                                                                    custom={}))
    assert