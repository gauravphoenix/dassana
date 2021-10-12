## Get Bucket Stats

Returns size-related statistics for an Amazon S3 Bucket  

### Sample Input:
```json
{
  "bucketName": "aws-cloudtrail-logs-032584774331-78c50f0b",
  "region": "us-east-2"
}
```

### Sample Output:
```json
{
  "result": {
    "bucketSizeInGB": 0.000466,
    "numberOfObjects": 287
  }
}
```
Note: Bucket metrics may take up to 24 hours to appear in Cloudwatch after creation
