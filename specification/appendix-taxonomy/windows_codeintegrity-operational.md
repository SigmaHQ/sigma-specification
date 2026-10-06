# product: windows, service: codeintegrity-operational

```yaml
logsource:
    product: windows
    service: codeintegrity-operational
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [Microsoft-Windows-CodeIntegrity / EventID: 3001](#microsoft-windows-codeintegrity--eventid-3001)
  - [Microsoft-Windows-CodeIntegrity / EventID: 3023](#microsoft-windows-codeintegrity--eventid-3023)
  - [Microsoft-Windows-CodeIntegrity / EventID: 3036](#microsoft-windows-codeintegrity--eventid-3036)
  - [Microsoft-Windows-CodeIntegrity / EventID: 3037](#microsoft-windows-codeintegrity--eventid-3037)
  - [Microsoft-Windows-CodeIntegrity / EventID: 3077](#microsoft-windows-codeintegrity--eventid-3077)
  - [Microsoft-Windows-CodeIntegrity / EventID: 3104](#microsoft-windows-codeintegrity--eventid-3104)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-CodeIntegrity/Operational

## Fields

The rules of this log source use the following field names:

- `EventID`
- `FileNameBuffer`
- `ProcessNameBuffer`
- `RequestedPolicy`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-CodeIntegrity / EventID: 3001

- `FileNameLength`
- `FileNameBuffer`

### Microsoft-Windows-CodeIntegrity / EventID: 3023

- `FileNameLength`
- `FileNameBuffer`

### Microsoft-Windows-CodeIntegrity / EventID: 3036

- `FileNameLength`
- `FileNameBuffer`

### Microsoft-Windows-CodeIntegrity / EventID: 3037

- `FileNameLength`
- `FileNameBuffer`

### Microsoft-Windows-CodeIntegrity / EventID: 3077

- `FileNameLength`
- `File Name`
- `ProcessNameLength`
- `Process Name`
- `Requested Signing Level`
- `Validated Signing Level`
- `Status`
- `SHA1 Hash Size`
- `SHA1 Hash`
- `SHA256 Hash Size`
- `SHA256 Hash`
- `USN`
- `SI Signing Scenario`

### Microsoft-Windows-CodeIntegrity / EventID: 3104

- `FileNameLength`
- `FileNameBuffer`

<!-- event-fields:end -->
