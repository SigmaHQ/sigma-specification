# category: registry_set, product: windows

```yaml
logsource:
    category: registry_set
    product: windows
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

Events written by Sysmon.

- EventID: 13
- Channel: Microsoft-Windows-Sysmon/Operational
- Sysmon events: RegistrySetValue

## Points of Attention

- The rules set `definition: 'Requirements: Sysmon config that monitors \SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController subkey of the HKLM hives'`.
- The rules set `definition: 'Requirements: Sysmon config that monitors \Keyboard Layout\Preload subkey of the HKLU hives - see https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files'`.
- The rules set `definition: 'Requirements: The registry key "\SOFTWARE\Microsoft\Provisioning\Commands\" and its subkey must be monitored'`.
- Only the registry keys and values that the configuration of Sysmon monitors are logged, a key that is not declared in it never produces an event.

## Fields

The rules of this log source use the following field names:

- `Details`
- `Image`
- `TargetObject`
- `User`
