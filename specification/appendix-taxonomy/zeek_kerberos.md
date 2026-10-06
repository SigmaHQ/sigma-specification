# product: zeek, service: kerberos

```yaml
logsource:
    product: zeek
    service: kerberos
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Kerberos tickets observed by Zeek on the network it monitors.

## Points of Attention

- The fields are the nested fields of the Zeek logs, `id.orig_h` for example is the address of the client.
- A Kerberos log has to be declared in the Zeek configuration to be written.

## Fields

The rules of this log source use the following field names:

- `cipher`
- `request_type`
- `service`
