# category: application, product: rpc_firewall

```yaml
logsource:
    category: application
    product: rpc_firewall
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Events of the RPC Firewall, a Windows firewall driver that filters the calls made to the RPC interfaces.

## Points of Attention

- Every rule declares in its `definition` the UUIDs of the RPC interfaces and the operation numbers that have to be blocked or audited on the processes of the host.

## Fields

The rules of this log source use the following field names:

- `EventID`
- `EventLog`
- `InterfaceUuid`
- `OpNum`
