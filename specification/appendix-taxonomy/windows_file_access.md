# category: file_access, product: windows

```yaml
logsource:
    category: file_access
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Files accessed by the processes of a Windows host, read from the kernel file provider.

## Telemetry

- Provider: Microsoft-Windows-Kernel-File

## Points of Attention

- The rules set `definition: 'Requirements: Microsoft-Windows-Kernel-File ETW provider'`. 6 rules use the same requirement.
- The provider is only enabled on Windows 10 and on Windows Server 2016 and later, the same events are written by Sysmon for the hosts that monitor it.

## Fields

The rules of this log source use the following field names:

- `FileName`
- `Image`
- `ParentImage`
