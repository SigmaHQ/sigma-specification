# product: zeek, service: smb_files

```yaml
logsource:
    product: zeek
    service: smb_files
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Files transferred with SMB observed by Zeek on the network it monitors.

## Points of Attention

- The fields are the nested fields of the Zeek logs, `id.orig_h` for example is the address of the client.
- An SMB file log has to be declared in the Zeek configuration to be written.

## Fields

The rules of this log source use the following field names:

- `name`
- `path`
