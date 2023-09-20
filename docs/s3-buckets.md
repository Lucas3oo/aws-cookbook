# Best practice for S3 buckets

## Logging
Recommendation is that you use CloudTrail for logging bucket-level and object-level actions for your Amazon S3 resources.

### Server access log
Access logs for a bucket is best saved in a target bucket, that is another bucket in same account and same region. 
The target bucket must not have a default retention period configuration. Your target bucket should not have server access logging enabled.

Use bucket policy to grant log delivery permissions (and not bucket ACL).

Only server-side encryption with Amazon S3 managed keys (SSE-S3) can be used on the target bucket.

The bucket policy on the target bucket needs to grant access to the logging service principal (logging.s3.amazonaws.com) for access log delivery.
The bucket policy must allow s3:PutObject access for the logging service principal.

```yaml
  AccessLogsS3BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref AccessLogsS3Bucket
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Action:
              - s3:PutObject
            Effect: Allow
            Resource: !Sub 'arn:${AWS::Partition}:s3:::${AccessLogsS3Bucket}/AWSLogs/*'
            Principal:
              Service: [logging.s3.amazonaws.com]
            Condition:
              StringEquals:
                aws:SourceAccount: !Ref AWS::AccountId
              ArnLike:
                aws:SourceArn: !Sub 'arn:aws:s3:::${S3Bucket}'

```

### Audit trail for API calls for S3
Use CloudTrail for S3 API calls. CloudTrail captures a subset of API calls for Amazon S3 as events.

CloudTrail does not deliver logs for requests that fail authentication (in which the provided credentials are not valid). 
However, it does include logs for requests in which authorization fails (AccessDenied) and requests that are made by anonymous users.

