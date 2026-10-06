# product: azure, service: signinlogs

```yaml
logsource:
    product: azure
    service: signinlogs
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Sign-in logs of Azure Active Directory and of Microsoft Entra ID, with the interactive and the non-interactive authentications.

## Points of Attention

- The result of the authentication is in `ResultType`, `0` meaning a successful authentication, its description is in `ResultDescription`.
- The rules of the repository match on the field names in the two spellings that the logs return, for example `ResultDescription` and `Resultdescription`.

## Fields

The rules of this log source use the following field names:

- `ActivityDetails`
- `AuthenticationRequirement`
- `ClientApp`
- `DeviceDetail.deviceId`
- `DeviceDetail.isCompliant`
- `DeviceDetail.trusttype`
- `NetworkLocationDetails`
- `ResourceDisplayName`
- `ResultDescription`
- `ResultType`
- `Resultdescription`
- `RiskState`
- `Status`
- `Username`
- `conditionalAccessStatus`
- `properties.message`
- `userAgent`
