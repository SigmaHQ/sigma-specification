# product: gcp, service: gcp.audit

```yaml
logsource:
    product: gcp
    service: gcp.audit
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Audit logs of Google Cloud, read from the Cloud Logging API.

## Points of Attention

- The log is identified by `logName`, for example `projects/<project>/logs/cloudaudit.googleapis.com%2Factivity`.
- The authorization of the call is in `data.protoPayload.authorizationInfo`, with the `permission` that was checked and if it was `granted`.

## Fields

The rules of this log source use the following field names:

- `data.protoPayload.authorizationInfo.granted`
- `data.protoPayload.authorizationInfo.permission`
- `data.protoPayload.logName`
- `data.protoPayload.methodName`
- `data.protoPayload.resource.type`
- `data.protoPayload.serviceName`
- `gcp.audit.method_name`
