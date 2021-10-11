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
    
def get_storage_metric(client, bucket_name, metric_name, storage_type):
    now = datetime.datetime.utcnow()
    
    response = client.get_metric_statistics(Namespace='AWS/S3',
                                        MetricName=metric_name,
                                        Dimensions=[
                                            {'Name': 'BucketName', 'Value': bucket_name},
                                            {'Name': 'StorageType', 'Value': storage_type}
                                        ],
                                        Statistics=['Average'],
                                        Period=86400,
                                        StartTime=(now-datetime.timedelta(days=2)).isoformat(), # StartTime-EndTime = 2*period in case single period has no datapoints
                                        EndTime=(now-datetime.timedelta(days=0)).isoformat()
                                        )
    
    response = loads(dumps(response, default=str))
    
    try:
        average_metric = response['Datapoints'][0]['Average']
    except Exception:
        average_metric = 0
    
    return average_metric

@validator(inbound_schema=schema)
def handle(event: Dict[str, Any], context: LambdaContext):
    cw_client = get_cached_client(dassana_aws.create_aws_client, context=context, service='cloudwatch',
                               region=event.get('region'))
    
    bucket_size = get_storage_metric(cw_client, event.get('bucketName'),'BucketSizeBytes', 'StandardStorage')
    
    # Convert bucket size from bytes to GB
    for i in range(3):
        bucket_size /= 1024
    
    bucket_size = round(bucket_size, 6)
    
    num_objects = get_storage_metric(cw_client, event.get('bucketName'), 'NumberOfObjects', 'AllStorageTypes')
    
    return {"result": {"bucketSizeInGB": bucket_size, "numberOfObjects": num_objects}}
