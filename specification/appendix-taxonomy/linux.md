# product: linux

```yaml
logsource:
    product: linux
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)

<!-- mdformat-toc end -->

## Description

Events of a Linux host that have no `service`, the rules of the rules repository match on the system logs of the host.

## Points of Attention

- The rules that match on the authentication and the authorization events need `/var/log/secure` on the Red Hat based systems or `/var/log/auth.log` on the Debian based systems to be collected.
