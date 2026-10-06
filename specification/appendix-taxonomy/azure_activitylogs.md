# product: azure, service: activitylogs

```yaml
logsource:
    product: azure
    service: activitylogs
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Activity logs of an Azure subscription, read with the Azure Monitor REST API.

## Points of Attention

- The operation is in `operationName` and in `OperationNameValue`, both spellings are used by the rules of the repository depending on how the log is parsed.

## Fields

The rules of this log source use the following field names:

- `CategoryValue`
- `OperationNameValue`
- `ResourceId`
- `ResourceProviderValue`
- `operationName`
- `properties.message`
