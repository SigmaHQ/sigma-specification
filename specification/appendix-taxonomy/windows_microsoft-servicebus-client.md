# product: windows, service: microsoft-servicebus-client

```yaml
logsource:
    product: windows
    service: microsoft-servicebus-client
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Events of the client library of the Azure Service Bus, with the connections it opened to the service.

## Points of Attention

- The rules of the rules repository give this log source a temporary name, until their validators support the one of the appendix, `service: servicebus-client`, see [windows_servicebus-client.md](windows_servicebus-client.md). Both pages have to be merged into a single one once the rules are updated.

## Fields

The rules of this log source use the following field names:

- `EventID`
