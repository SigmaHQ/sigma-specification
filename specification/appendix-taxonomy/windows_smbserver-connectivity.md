# product: windows, service: smbserver-connectivity

```yaml
logsource:
    product: windows
    service: smbserver-connectivity
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Connectivity events of the SMB server of a Windows host, with the shares that were accessed.

## Fields

The rules of this log source use the following field names:

- `EventID`
- `ShareName`
