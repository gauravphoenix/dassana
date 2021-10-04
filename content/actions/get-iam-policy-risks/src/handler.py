from json import load, loads, dumps
from typing import Dict, Any
import time

from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.utilities.validation import validator
from dassana.common.aws_client import DassanaAwsObject, parse_arn

from cloudsplaining.scan.policy_document import PolicyDocument
from cloudsplaining.shared.exclusions import Exclusions
from cloudsplaining.output.policy_finding import PolicyFinding

with open('input.json', 'r') as schema:
    schema = load(schema)
    dassana_aws = DassanaAwsObject()


def cloudsplaining_parse(policy_document, exclusions_config):
    policy_document = PolicyDocument(policy_document)
    exclusions = Exclusions(exclusions_config)
    policy_finding = PolicyFinding(policy_document, exclusions)
    return policy_document, exclusions, policy_finding


@validator(inbound_schema=schema)
def handle(event: Dict[str, Any], context: LambdaContext):
    policies = []
    policy_statements = []
    exclusions_config = {}

    iam_arn = parse_arn(event.get('iamArn'))
    client = dassana_aws.create_aws_client(context, 'iam', event.get('region'))

    name = iam_arn.resource
    resource_type = iam_arn.resource_type

    if resource_type == 'role':
        paginator = client.get_paginator('list_attached_role_policies')

        page_iterator = paginator.paginate(
            RoleName=name,
            PathPrefix='/'
        )

        try:
            for page in page_iterator:
                for policy in page['AttachedPolicies']:
                    policies.append({
                        'PolicyArn': policy['PolicyArn'],
                        'PolicyName': policy['PolicyName']
                    })
        except Exception:
            pass

        paginator = client.get_paginator('list_role_policies')

        page_iterator = paginator.paginate(
            RoleName=name
        )

        try:
            for page in page_iterator:
                for policy_name in page['PolicyNames']:
                    policies.append({
                        'PolicyName': policy_name,
                        'PolicyArn': ''
                    })
        except Exception:
            # TODO: add error handling
            pass

    elif resource_type == 'user':
        paginator = client.get_paginator('list_attached_user_policies')

        page_iterator = paginator.paginate(
            UserName=name,
            PathPrefix='/'
        )
        try:
            for page in page_iterator:
                for policy in page['AttachedPolicies']:
                    policies.append({
                        'PolicyArn': policy['PolicyArn'],
                        'PolicyName': policy['PolicyName']
                    })
        except Exception:
            # TODO: add error handling
            pass

        paginator = client.get_paginator('list_user_policies')

        page_iterator = paginator.paginate(
            UserName=name
        )
        try:
            for page in page_iterator:
                for policy_name in page['PolicyNames']:
                    policies.append({
                        'PolicyName': policy_name,
                        'PolicyArn': ''
                    })
        except Exception:
            pass

    elif resource_type == 'policy':
        policies.append({
            'PolicyArn': iam_arn,
            'PolicyName': name
        })

    for policy in policies:
        if policy['PolicyArn'] != '':
            policy_basic = client.get_policy(
                PolicyArn=policy['PolicyArn']
            )
            policy_detailed = client.get_policy_version(
                PolicyArn=policy['PolicyArn'],
                VersionId=policy_basic['Policy']['DefaultVersionId']
            )
            policy_document = policy_detailed['PolicyVersion']['Document']
        else:
            policy_detailed = client.get_role_policy(
                RoleName=name,
                PolicyName=policy['PolicyName']
            )
            policy_document = policy_detailed['PolicyDocument']

        policy_statements += policy_document['Statement']

    policy_document = {
        'Statement': policy_statements
    }

    policy_document, exclusions, policy_finding = cloudsplaining_parse(policy_document, exclusions_config)

    response = dumps({
        'PolicyFindings': policy_finding.results
    }, default=str)

    return {"result": loads(response)}
