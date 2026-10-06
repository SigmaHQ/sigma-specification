# product: zeek, service: dce_rpc

```yaml
logsource:
    product: zeek
    service: dce_rpc
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

DCE RPC calls observed by Zeek on the network it monitors.

## Points of Attention

- The fields are the nested fields of the Zeek logs, `id.orig_h` for example is the address of the originator of the connection.
- The rules match on the `endpoint` of the RPC interface and on the `operation` that was called on it.

## Fields

The rules of this log source use the following field names:

- `endpoint`
- `operation`
