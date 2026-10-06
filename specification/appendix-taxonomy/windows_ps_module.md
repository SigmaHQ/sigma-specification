# product: windows, category: ps_module

```yaml
logsource:
    product: windows
    category: ps_module
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
  - [PowerShell 5](#powershell-5)
  - [PowerShell 7](#powershell-7)
- [Points of Attention](#points-of-attention)
  - [Microsoft-Windows-PowerShell](#microsoft-windows-powershell)
  - [PowerShellCore](#powershellcore)
- [Fields](#fields)
  - [Microsoft-Windows-PowerShell / EventID: 4103](#microsoft-windows-powershell--eventid-4103)
  - [PowerShellCore / EventID: 4103](#powershellcore--eventid-4103)

<!-- mdformat-toc end -->

## Description

Modules loaded by the PowerShell engines, with the pipeline execution details of each one. The category is covered by the two editions of PowerShell, they are described in this page.

## Telemetry

### PowerShell 5

- Provider: Microsoft-Windows-PowerShell
- Channel: Microsoft-Windows-PowerShell/Operational
- EventID: 4103

### PowerShell 7

- Provider: PowerShellCore
- Channel: PowerShellCore/Operational
- EventID: 4103

## Points of Attention

This section copies the logsource guide [`documentation/logsource-guides/windows/category/ps_module.md`](https://github.com/SigmaHQ/sigma/blob/master/documentation/logsource-guides/windows/category/ps_module.md) of the rules repository.

- The two editions write the same fields, but they log to two different channels. A rule that has to match on both has to be collected from `Microsoft-Windows-PowerShell/Operational` and from `PowerShellCore/Operational`.
- The events are only written when module logging is enabled and when the module is in the list of the modules to log.
- The event volume depends on the modules that are logged, it is low for a default configuration that only logs the Windows modules.

### Microsoft-Windows-PowerShell

Enable module logging with the `gpedit.msc` or with an equivalent tool:

```text
- Computer Configuration
    - Administrative Templates
        - Windows Components
            - Windows PowerShell
                - Turn On Module Logging
                    - Select List Of Modules According To Your Audit Policy
```

Use `*` to select all the modules.

### PowerShellCore

Enable module logging with the `gpedit.msc` or with an equivalent tool:

```text
- Computer Configuration
    - Administrative Templates
        - Windows PowerShell Core
            - Turn On Module Logging
                - Select List Of Modules According To Your Audit Policy
```

> [!NOTE]
> The logging template of PowerShell 7 isn't installed with the product. Install it with the `InstallPSCorePolicyDefinitions.ps1` script of the installation directory.

## Fields

### Microsoft-Windows-PowerShell / EventID: 4103

- `ContextInfo`
- `UserData`
- `Payload`

### PowerShellCore / EventID: 4103

- `ContextInfo`
- `UserData`
- `Payload`
