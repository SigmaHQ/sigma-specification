# product: zeek, service: x509

```yaml
logsource:
    product: zeek
    service: x509
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Certificates seen by Zeek in the TLS handshakes of the network it monitors.

## Points of Attention

- The fields are the nested fields of the Zeek logs, `certificate.serial` for example is the serial number of the certificate.
- An X.509 log has to be declared in the Zeek configuration to be written.

## Fields

The rules of this log source use the following field names:

- `certificate.serial`
