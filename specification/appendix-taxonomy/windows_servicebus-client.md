# product: windows, service: servicebus-client

```yaml
logsource:
    product: windows
    service: servicebus-client
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)

<!-- mdformat-toc end -->

## Description

Events of the client library of the Azure Service Bus, with the connections it opened to the service.

## Telemetry

- Channels:
  - Microsoft-ServiceBus-Client/Operational
  - Microsoft-ServiceBus-Client/Admin

## Points of Attention

- The rules of the rules repository use the temporary log source `service: microsoft-servicebus-client` until their validators support this name, see [windows_microsoft-servicebus-client.md](windows_microsoft-servicebus-client.md). Both pages have to be merged into a single one once the rules are updated.
