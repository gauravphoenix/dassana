from json import load, loads, dumps
from typing import Dict, Any
import datetime

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
    cw_client = get_cached_client(dassana_aws.create_aws_client, context=context, service='cloudwatch',
                               region=event.get('region'))

    now = datetime.datetime.utcnow()

    response = cw_client.get_metric_statistics(Namespace='AWS/S3',
                                        MetricName='BucketSizeBytes',
                                        Dimensions=[
                                            {'Name': 'BucketName', 'Value': event.get('bucketName')},
                                            {'Name': 'StorageType', 'Value': 'StandardStorage'}
                                        ],
                                        Statistics=['Average'],
                                        Period=86400,
                                        StartTime=(now-datetime.timedelta(days=1)).isoformat(),
                                        EndTime=(now-datetime.timedelta(days=0)).isoformat()
                                        )
    
    cw_response = loads(dumps(response, default=str))
    
    try:
        bucketSize = response['Datapoints'][0]['Average']
    except Exception:
        bucketSize = 0
    
    for i in range(3):
        bucketSize /= 1024
    
    bucketSize = round(bucketSize, 6)
        
    response = cw_client.get_metric_statistics(Namespace='AWS/S3',
                                        MetricName='NumberOfObjects',
                                        Dimensions=[
                                            {'Name': 'BucketName', 'Value': event.get('bucketName')},
                                            {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
                                        ],
                                        Statistics=['Average'],
                                        Period=86400,
                                        StartTime=(now-datetime.timedelta(days=1)).isoformat(),
                                        EndTime=(now-datetime.timedelta(days=0)).isoformat()
                                        )
                                        
    cw_response = loads(dumps(response, default=str))
    
    try:
        numberOfObjects = response['Datapoints'][0]['Average']
    except Exception:
        numberOfObjects = 0
    
    return {"result": {"bucketSizeInGB": bucketSize, "numberOfObjects": numberOfObjects}}
