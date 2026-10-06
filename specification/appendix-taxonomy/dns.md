# category: dns

```yaml
logsource:
    category: dns
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

DNS queries and answers logged by a DNS server. The rules match on the queried name, on the answers and on the record type.

## Points of Attention

- The field names are the ones used by the rules of the repository, the DNS servers write their logs with their own field names.

## Fields

The rules of this log source use the following field names:

- `answer`
- `query`
- `record_type`
