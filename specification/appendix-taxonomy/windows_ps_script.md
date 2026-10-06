# product: windows, category: ps_script

```yaml
logsource:
    product: windows
    category: ps_script
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
  - [Microsoft-Windows-PowerShell / EventID: 4104](#microsoft-windows-powershell--eventid-4104)
  - [PowerShellCore / EventID: 4104](#powershellcore--eventid-4104)

<!-- mdformat-toc end -->

## Description

Script blocks of the PowerShell engines, with the text of the code that was compiled. The category is covered by the two editions of PowerShell, they are described in this page.

## Telemetry

### PowerShell 5

- Provider: Microsoft-Windows-PowerShell
- Channel: Microsoft-Windows-PowerShell/Operational
- EventID: 4104

### PowerShell 7

- Provider: PowerShellCore
- Channel: PowerShellCore/Operational
- EventID: 4104

## Points of Attention

This section copies the logsource guide [`documentation/logsource-guides/windows/category/ps_script.md`](https://github.com/SigmaHQ/sigma/blob/master/documentation/logsource-guides/windows/category/ps_script.md) of the rules repository.

- The two editions write the same fields, but they log to two different channels. A rule that has to match on both has to be collected from `Microsoft-Windows-PowerShell/Operational` and from `PowerShellCore/Operational`.
- The events are only written when script block logging is enabled.
- The rules of the repository declare the requirement in their `definition`, for example `Requirements: Script Block Logging must be enabled`.
- A long script is split over several events, `ScriptBlockText` of one event is only a part of the script. `MessageNumber` and `MessageTotal` tell which part the event holds.
- The event volume is high when a script block logging is enabled on a host that runs many scripts.

### Microsoft-Windows-PowerShell

Enable script block logging with the `gpedit.msc` or with an equivalent tool:

```text
- Computer Configuration
    - Administrative Templates
        - Windows Components
            - Windows PowerShell
                - Turn On PowerShell Script Block Logging
```

### PowerShellCore

Enable script block logging with the `gpedit.msc` or with an equivalent tool:

```text
- Computer Configuration
    - Administrative Templates
        - Windows PowerShell Core
            - Turn On PowerShell Script Block Logging
```

> [!NOTE]
> The logging template of PowerShell 7 isn't installed with the product. Install it with the `InstallPSCorePolicyDefinitions.ps1` script of the installation directory.

## Fields

### Microsoft-Windows-PowerShell / EventID: 4104

- `MessageNumber`
- `MessageTotal`
- `ScriptBlockText`
- `ScriptBlockId`
- `Path`

### PowerShellCore / EventID: 4104

- `MessageNumber`
- `MessageTotal`
- `ScriptBlockText`
- `ScriptBlockId`
- `Path`
