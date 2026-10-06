# product: zeek, service: dns

```yaml
logsource:
    product: zeek
    service: dns
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

DNS queries and answers observed by Zeek on the network it monitors.

## Points of Attention

- The fields are the nested fields of the Zeek logs, `id.orig_h` for example is the address of the host that sent the query.
- A DNS log has to be declared in the Zeek configuration to be written.

## Fields

The rules of this log source use the following field names:

- `Z`
- `answers`
- `id.resp_p`
- `qtype_name`
- `query`
- `rejected`
