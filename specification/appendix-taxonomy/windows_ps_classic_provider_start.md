# category: ps_classic_provider_start, product: windows

```yaml
logsource:
    category: ps_classic_provider_start
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Start events of the Windows PowerShell engine.

## Telemetry

- EventID: 600
- Channel: Windows PowerShell

## Points of Attention

- The payload is in the `Data` field of the event, the pipeline has to parse it to make the rules match on the command line.

## Fields

The rules of this log source use the following field names:

- `Data`
