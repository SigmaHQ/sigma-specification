# product: aws, service: cloudtrail

```yaml
logsource:
    product: aws
    service: cloudtrail
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Records of the AWS CloudTrail, that is the API calls made against an AWS account, with the identity that made the call and its result.

## Points of Attention

- The fields are nested, the rules reach them with the dotted notation, `userIdentity.arn` for example.
- The management events are logged by default, the data events have to be enabled for each resource type that has to be monitored.
- The records are collected from the CloudTrail API or from the S3 bucket, the field names are the same in both cases.

## Fields

The rules of this log source use the following field names:

- `additionalEventData.MFAUsed`
- `errorCode`
- `errorMessage`
- `eventName`
- `eventSource`
- `eventType`
- `requestParameters`
- `requestParameters.attribute`
- `requestParameters.containerDefinitions.command`
- `requestParameters.enable`
- `requestParameters.layers`
- `responseElements`
- `responseElements.ConsoleLogin`
- `responseElements.pendingModifiedValues.masterUserPassword`
- `responseElements.publiclyAccessible`
- `status`
- `userAgent`
- `userIdentity.arn`
- `userIdentity.sessionContext.sessionIssuer.type`
- `userIdentity.type`
