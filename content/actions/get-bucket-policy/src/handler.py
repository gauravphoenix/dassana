from json import load, loads, dumps
from typing import Dict, Any

from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.utilities.validation import validator
from dassana.common.aws_client import DassanaAwsObject
from dassana.common.cache import configure_ttl_cache

with open('input.json', 'r') as schema:
    schema = load(schema)
    dassana_aws = DassanaAwsObject()
    
get_cached_client = configure_ttl_cache(1024, 60)

@validator(inbound_schema=schema)
def handle(event: Dict[str, Any], context: LambdaContext):
    client = get_cached_client(dassana_aws.create_aws_client, context=context, service='s3',
                               region=event.get('region'))

    bucket_name = event.get('bucketName')
    
    try:
        result = client.get_bucket_policy(Bucket=bucket_name)
        bucket_policy = result['Policy']
    except Exception:
        # The bucket does not have an associated bucket policy
        bucket_policy = {}
    
    return {"result": loads(bucket_policy)}
