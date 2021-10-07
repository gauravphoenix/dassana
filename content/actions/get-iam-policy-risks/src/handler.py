from json import load, loads, dumps
from typing import Dict, Any

from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.utilities.validation import validator
from dassana.common.aws_client import DassanaAwsObject, parse_arn

from cloudsplaining.scan.policy_document import PolicyDocument
from cloudsplaining.shared.exclusions import Exclusions
from cloudsplaining.output.policy_finding import PolicyFinding

from dassana.common.cache import configure_ttl_cache, configure_lru_cache

with open('input.json', 'r') as schema:
    schema = load(schema)
    dassana_aws = DassanaAwsObject()


def cloudsplaining_parse(policy_document, exclusions_config=None) -> PolicyFinding:
    if exclusions_config is None:
        exclusions_config = {}
    policy_document = PolicyDocument(policy_document)
    exclusions = Exclusions(exclusions_config)
    return get_cached_findings(PolicyFinding, policy_document=policy_document, exclusions=exclusions)


get_cached_client_aws = configure_ttl_cache(1024, 60)
get_cached_findings = configure_lru_cache(1024)


@validator(inbound_schema=schema)
def handle(event: Dict[str, Any], context: LambdaContext):
    policies = []
    policy_statements = []
    exclusions_config = {}

    iam_arn = parse_arn(event.get('iamArn'))
    name = iam_arn.resource
    resource_type = iam_arn.resource_type

    client = get_cached_client_aws(dassana_aws.create_aws_client, context=context, service='iam',
                                   region=event.get('region'))

	POLICY_ARN = 'PolicyArn'
	POLICY_NAME = 'PolicyName'

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
                        POLICY_ARN: policy[POLICY_ARN],
                        POLICY_NAME: policy[POLICY_NAME]
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
                        POLICY_ARN: '',
                        POLICY_NAME: policy_name
                    })
        except Exception:
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
                        POLICY_ARN: policy[POLICY_ARN],
                        POLICY_NAME: policy[POLICY_NAME]
                    })
        except Exception:
            pass

        paginator = client.get_paginator('list_user_policies')

        page_iterator = paginator.paginate(
            UserName=name
        )
        try:
            for page in page_iterator:
                for policy_name in page['PolicyNames']:
                    policies.append({
                        POLICY_ARN: '',
                        POLICY_NAME: policy_name
                    })
        except Exception:
            pass

    elif resource_type == 'policy':
        policies.append({
            POLICY_ARN: iam_arn,
            POLICY_NAME: name
        })

    for policy in policies:
        if policy[POLICY_ARN] != '':
            policy_basic = client.get_policy(
                PolicyArn=policy[POLICY_ARN]
            )
            policy_detailed = client.get_policy_version(
                PolicyArn=policy[POLICY_ARN],
                VersionId=policy_basic['Policy']['DefaultVersionId']
            )
            policy_document = policy_detailed['PolicyVersion']['Document']
        else:
            policy_detailed = client.get_role_policy(
                RoleName=name,
                PolicyName=policy[POLICY_NAME]
            )
            policy_document = policy_detailed['PolicyDocument']

        policy_statements += policy_document['Statement']

    policy_document = {
        'Statement': policy_statements
    }

    policy_finding = cloudsplaining_parse(policy_document, exclusions_config)

    response = dumps({
        'PolicyFindings': policy_finding.results
    }, default=str)

    return {"result": loads(response)}
