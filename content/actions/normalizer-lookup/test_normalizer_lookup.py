from dassana.common.aws_client import LambdaTestContext
from json import dumps
from copy import deepcopy
import pytest
import os

ROOT_DIR = ''.join(os.path.abspath(os.curdir).partition('dassana')[:2])


@pytest.fixture(autouse=True)
def mock_workflow_dir(monkeypatch):
    monkeypatch.setenv('WORKFLOW_DIR', '%s/content/workflows/csp/**/*.yaml' % ROOT_DIR)


class TestPrismaLookup:
    @pytest.fixture()
    def nothing_missing(self):
        return {
            'input':
                {
                    "vendorId": "prisma-cloud",
                    "alertId": "P-210",
                    "canonicalId": None,
                    "vendorPolicy": "e50e3c0a-01ac-48fc-8972-f1313c72de71",
                    "csp": "aws",
                    "resourceContainer": "foobar",
                    "region": "eu-central-1",
                    "service": "ec2",
                    "alertClassification": {
                        "class": "risk",
                        "subclass": "config",
                        "category": "networking",
                        "subcategory": "firewall"
                    },
                    "resourceType": "network-acl",
                    "resourceId": "acl-8d506ce7",
                    "tags": []
                }
        }

    @pytest.fixture()
    def alert_classification_missing(self, nothing_missing):
        nothing_missing_cpy = deepcopy(nothing_missing)
        nothing_missing_cpy.get('input').pop('alertClassification')
        return nothing_missing_cpy

    def test_no_lookup(self, nothing_missing):
        from handler import handle
        result = handle(nothing_missing, LambdaTestContext('abc'))
        assert dumps(result, sort_keys=True) == dumps(nothing_missing.get('input'), sort_keys=True)

    @pytest.mark.parametrize("field", ["service", "resourceType", "alertClassification"])
    def test_lookup_missing(self, field, nothing_missing):
        from handler import handle
        cpy = deepcopy(nothing_missing)
        cpy.get('input').pop(field)
        result = handle(cpy, LambdaTestContext('abc'))

        original_value = nothing_missing.get('input').get(field)
        if type(original_value) == str:
            assert result.get(field) == original_value
        else:
            assert result.get(field) == {
                **original_value
            }


class TestGuarddutyLookup:
    @pytest.fixture()
    def nothing_missing(self):
        return {
            "input": {
                "csp": "aws",
                "alertClassification": {
                    "class": "incident",
                    "subclass": "credential-access",
                    "category": "brute-force",
                    "subcategory": ""
                },
                "resourceId": "i-foobar",
                "canonicalId": "arn:aws:ec2:us-east-1:foobar:instance/i-foobar",
                "service": "ec2",
                "vendorPolicy": "UnauthorizedAccess:EC2/SSHBruteForce",
                "vendorId": "aws-guardduty",
                "alertId": "arn:aws:guardduty:us-east-1:foobar:detector/foobar",
                "resourceContainer": "foobar",
                "region": "us-east-1",
                "resourceType": "instance",
                "tags": []
            }
        }

    @pytest.fixture()
    def alert_classification_missing(self, nothing_missing):
        nothing_missing_cpy = deepcopy(nothing_missing)
        nothing_missing_cpy.get('input').pop('alertClassification')
        return nothing_missing_cpy

    def test_no_lookup(self, nothing_missing):
        from handler import handle
        result = handle(nothing_missing, LambdaTestContext('abc'))
        assert dumps(result, sort_keys=True) == dumps(nothing_missing.get('input'), sort_keys=True)

    @pytest.mark.parametrize("field", ["service", "resourceType", "alertClassification"])
    def test_lookup_missing(self, field, nothing_missing):
        from handler import handle
        cpy = deepcopy(nothing_missing)
        cpy.get('input').pop(field)
        result = handle(cpy, LambdaTestContext('abc'))

        original_value = nothing_missing.get('input').get(field)
        if type(original_value) == str:
            assert result.get(field) == original_value
        else:
            assert result.get(field) == {
                **original_value
            }
