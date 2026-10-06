# service: nginx

```yaml
logsource:
    service: nginx
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)

<!-- mdformat-toc end -->

## Description

The error log of the nginx HTTP server.

## Telemetry

The `error.log` file, written by the master and the worker processes. The rules are keyword rules and match on the message text, not on fields.

- File: error.log

## Points of Attention

- The message the rules match on, `exited on signal 6 (core dumped)`, is written at the `error` level, which nginx logs by default.
