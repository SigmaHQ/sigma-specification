# product: windows, service: powershell-classic

```yaml
logsource:
    product: windows
    service: powershell-classic
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Events of the Windows PowerShell engine that is the classic edition, Windows PowerShell 2.0 to 5.1, written to the `Windows PowerShell` channel.

## Telemetry

- Channel: Windows PowerShell

## Points of Attention

- The payload is in the `Data` field of the event, the pipeline has to parse it to make the rules match on the command line.

## Fields

The rules of this log source use the following field names:

- `Data`
