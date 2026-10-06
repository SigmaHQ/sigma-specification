# product: azure, service: auditlogs

```yaml
logsource:
    product: azure
    service: auditlogs
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Audit logs of Azure Active Directory, read with the Microsoft Graph API.

## Points of Attention

- The rules set `definition: 'Requirements: The TargetResources array needs to be mapped accurately in order for this rule to work'`.
- `TargetResources` is an array with one entry per modified object, a rule that matches on the modified properties has to map the array before the rule can be used.
- The rules of the repository match on the field names in the two spellings that the API returns, for example `properties.targetResources` and `targetResources`.

## Fields

The rules of this log source use the following field names:

- `ActivityDisplayName`
- `ActivityType`
- `Category`
- `ConsentContext.IsAdminConsent`
- `Initiatedby`
- `LoggedByService`
- `OperationName`
- `Status`
- `Target`
- `TargetResources`
- `TargetResources.ModifiedProperties.DisplayName`
- `TargetResources.ModifiedProperties.NewValue`
- `TargetResources.modifiedProperties`
- `TargetResources.modifiedProperties.newValue`
- `activityType`
- `additionalDetails.additionalInfo`
- `category`
- `failure_status_reason`
- `operationName`
- `properties.message`
- `properties.result`
- `properties.targetResources`
- `targetResources.type`
