# product: linux, service: auth

```yaml
logsource:
    product: linux
    service: auth
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)

<!-- mdformat-toc end -->

## Description

Authentication and authorization events of a Linux host.

## Telemetry

Events written to the system log by the authentication service of the host.

## Points of Attention

- The file is `/var/log/secure` on the Red Hat based systems and `/var/log/auth.log` on the Debian based systems, one of the two has to be collected.
