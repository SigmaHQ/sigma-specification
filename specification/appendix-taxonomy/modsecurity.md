# product: modsecurity

```yaml
logsource:
    product: modsecurity
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)

<!-- mdformat-toc end -->

## Description

The audit log of the ModSecurity web application firewall.

## Telemetry

The entries the module writes when it blocks a request. The rules are keyword rules and match on the message text, not on fields.

Depending on the web server the module protects, the entries are written to its error log or to the system event log.

## Points of Attention

- The rules that use this log source live in the `unsupported` directory of the rules repository, they aren't part of the shared rule base yet.
