# service: apache

```yaml
logsource:
    service: apache
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)

<!-- mdformat-toc end -->

## Description

The error log of the Apache HTTP server.

## Telemetry

The `error.log` file, written by the server processes. The rules are keyword rules and match on the message text, not on fields.

- File: error.log

## Points of Attention

- The error log has to be collected on the host, the rules declare it with `definition: 'Requirements: Must be able to collect the error.log file'`.
- The messages the rules match on are written at the `error` level, which the default `LogLevel warn` includes.
