# product: zeek, service: http

```yaml
logsource:
    product: zeek
    service: http
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

HTTP requests and responses observed by Zeek on the network it monitors.

## Points of Attention

- The fields are the nested fields of the Zeek logs, `id.orig_h` for example is the address of the client.
- An HTTP log has to be declared in the Zeek configuration to be written.

## Fields

The rules of this log source use the following field names:

- `host`
- `id.resp_h`
- `method`
- `resp_mime_types`
- `uri`
- `user_agent`
