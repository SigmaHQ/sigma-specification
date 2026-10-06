# product: cisco, service: duo

```yaml
logsource:
    product: cisco
    service: duo
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Authentication events of Cisco Duo, read from the logs of the Duo Admin API.

## Points of Attention

- The rules match on `event_type` and on `reason`, the two fields that describe why the authentication was accepted or denied.

## Fields

The rules of this log source use the following field names:

- `event_type`
- `reason`
