## Retrieve the bucket policy for a given Amazon S3 bucket

Returns the provided S3 bucket's policy 

### Sample Input:
```json
{
  "bucketName": "aws-cloudtrail-logs-032584774331-78c50f0b"
}
```

### Sample Output:
```json
{
  "result": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AWSCloudTrailAclCheck20150319",
        "Effect": "Allow",
        "Principal": {
          "Service": "cloudtrail.amazonaws.com"
        },
        "Action": "s3:GetBucketAcl",
        "Resource": "arn:aws:s3:::aws-cloudtrail-logs-032584774331-78c50f0b"
      },
      {
        "Sid": "AWSCloudTrailWrite20150319",
        "Effect": "Allow",
        "Principal": {
          "Service": "cloudtrail.amazonaws.com"
        },
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::aws-cloudtrail-logs-032584774331-78c50f0b/AWSLogs/032584774331/*",
        "Condition": {
          "StringEquals": {
            "s3:x-amz-acl": "bucket-owner-full-control"
          }
        }
      }
    ]
  }
}
```
