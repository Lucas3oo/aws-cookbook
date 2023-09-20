# Best practice for S3 buckets

## Logging
Recommendation is that you use CloudTrail for logging bucket-level and object-level actions for your Amazon S3 resources.

### CloudTrail logging for S3
Use CloudTrail for S3 API calls. CloudTrail captures a subset of API calls for Amazon S3 as events.

CloudTrail does not deliver logs for requests that fail authentication (in which the provided credentials are not valid). 
However, it does include logs for requests in which authorization fails (AccessDenied) and requests that are made by anonymous users.

```yaml
---
AWSTemplateFormatVersion: 2010-09-09
Description: Bucket with cloud trail log demo

Parameters:
  S3BucketName:
    Type: String
    Default: slrk-my-demo-bucket2

Resources:
  S3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
      BucketName: !Ref S3BucketName
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true

  S3BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref S3Bucket
      PolicyDocument:
        Statement:
          - Sid: DenyNonTLSRequests
            Effect: Deny
            Action: s3:*
            Resource:
              - !Sub "arn:${AWS::Partition}:s3:::${S3Bucket}"
              - !Sub "arn:${AWS::Partition}:s3:::${S3Bucket}/*"
            Principal: "*"
            Condition:
              Bool:
                aws:SecureTransport: false

  AccessLogsS3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${S3BucketName}-s3-cloud-trail-logs"
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      Tags:
        - Key: Description
          Value: S3 bucket for the S3 cloud trail log.

  AccessLogsS3BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref AccessLogsS3Bucket
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Action:
              - s3:GetBucketAcl
            Effect: Allow
            Resource: !Sub "arn:${AWS::Partition}:s3:::${AccessLogsS3Bucket}"
            Principal:
              Service: [cloudtrail.amazonaws.com]
          - Action:
              - s3:PutObject
            Effect: Allow
            Resource: !Sub "arn:${AWS::Partition}:s3:::${AccessLogsS3Bucket}/*"
            Principal:
              Service: [cloudtrail.amazonaws.com]
            Condition:
              StringEquals:
                s3:x-amz-acl: "bucket-owner-full-control"

  CloudTrail:
    Type: AWS::CloudTrail::Trail
    DependsOn:
      - AccessLogsS3BucketPolicy
    Properties:
      EnableLogFileValidation: true
      EventSelectors:
        - DataResources:
            - Type: AWS::S3::Object
              Values:
                - !Sub "arn:${AWS::Partition}:s3:::${S3Bucket}/"
          IncludeManagementEvents: false
          # Capture read-only events for the bucket.
          ReadWriteType: ReadOnly
      IsLogging: true
      IsMultiRegionTrail: false
      IsOrganizationTrail: false
      S3BucketName: !Ref AccessLogsS3Bucket

```

### Server access log
Server access logging is "best effort" buy AWS so better use CloudTrail instead for access logging. Only benefit is that server access logging logs authentication failure.
Access logs for a bucket is best saved in a target bucket, that is another bucket in same account and same region. 
The target bucket must not have a default retention period configuration. Your target bucket should not have server access logging enabled.

Use bucket policy to grant log delivery permissions (and not bucket ACL).

Only server-side encryption with Amazon S3 managed keys (SSE-S3) can be used on the target bucket.

The bucket policy on the target bucket needs to grant access to the logging service principal (logging.s3.amazonaws.com) for access log delivery.
The bucket policy must allow s3:PutObject access for the logging service principal.

It can take hours before the log shows up.

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Bucket log demo

Parameters:
  S3BucketName:
    Type: String
    Default: slrk-my-demo-bucket

Resources:
  S3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
      BucketName: !Ref S3BucketName
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      LoggingConfiguration:
        DestinationBucketName: !Ref AccessLogsS3Bucket
        LogFilePrefix: awsAccessLogs

  S3BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref S3Bucket
      PolicyDocument:
        Statement:
          - Sid: DenyNonTLSRequests
            Effect: Deny
            Action: s3:*
            Resource:
              - !Sub "arn:${AWS::Partition}:s3:::${S3Bucket}"
              - !Sub "arn:${AWS::Partition}:s3:::${S3Bucket}/*"
            Principal: "*"
            Condition:
              Bool:
                aws:SecureTransport: false

  AccessLogsS3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${S3BucketName}-s3-access-logs"
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      Tags:
        - Key: Description
          Value: S3 bucket for the S3 access log.

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
            Resource: !Sub "arn:${AWS::Partition}:s3:::${AccessLogsS3Bucket}/*"
            Principal:
              Service: [logging.s3.amazonaws.com]
            Condition:
              StringEquals:
                aws:SourceAccount: !Ref AWS::AccountId
              ArnLike:
                aws:SourceArn: !GetAtt S3Bucket.Arn
```

