# product: windows, service: appxdeployment-server

```yaml
logsource:
    product: windows
    service: appxdeployment-server
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Fields](#fields)
  - [Microsoft-Windows-AppXDeployment-Server / EventID: 400](#microsoft-windows-appxdeployment-server--eventid-400)
  - [Microsoft-Windows-AppXDeployment-Server / EventID: 401](#microsoft-windows-appxdeployment-server--eventid-401)
  - [Microsoft-Windows-AppXDeployment-Server / EventID: 412](#microsoft-windows-appxdeployment-server--eventid-412)
  - [Microsoft-Windows-AppXDeployment-Server / EventID: 603](#microsoft-windows-appxdeployment-server--eventid-603)
  - [Microsoft-Windows-AppXDeployment-Server / EventID: 854](#microsoft-windows-appxdeployment-server--eventid-854)

<!-- mdformat-toc end -->

## Telemetry

- Channel: Microsoft-Windows-AppXDeploymentServer/Operational

## Fields

The rules of this log source use the following field names:

- `CallingProcess`
- `ErrorCode`
- `EventID`
- `Flags`
- `HasFullTrust`
- `PackageFullName`
- `PackageSourceUri`
- `Path`

<!-- event-fields:start -->

The fields written for the event identifiers of the `## Telemetry` section, from the [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources) manifests and provider CSVs. Event identifiers the source doesn't document are left out.

### Microsoft-Windows-AppXDeployment-Server / EventID: 400

- `DeploymentOperation`
- `PackageFullName`
- `Path`
- `MountPoint`
- `TargetPlatform`
- `SystemVolume`
- `StorageId`
- `IsCentennial`
- `PackageType`
- `IsPackageEncrypted`
- `DeploymentOptions`
- `IsStreamingPackage`
- `IsInRelatedSet`
- `IsPackageUsingBDC`
- `MainPackageFamilyName`
- `CallingProcess`
- `IsOptional`
- `PackageFlags`
- `PackageFlags2`
- `HasWin32alacarte`
- `HasFullTrust`
- `ExternalLocation`
- `PackageSourceUri`
- `PackageDisplayName`

### Microsoft-Windows-AppXDeployment-Server / EventID: 401

- `DeploymentOperation`
- `PackageFullName`
- `Path`
- `ErrorCode`
- `MountPoint`
- `TargetPlatform`
- `SystemVolume`
- `StorageId`
- `IsCentennial`
- `PackageType`
- `IsPackageEncrypted`
- `DeploymentOptions`
- `IsStreamingPackage`
- `IsInRelatedSet`
- `IsPackageUsingBDC`
- `MainPackageFamilyName`
- `CallingProcess`
- `IsInPlaceUpdate`
- `ErrorFileInfo`
- `DetailedMessageInfo`
- `RollbackErrorFileInfo`
- `RollbackDetailedMessageInfo`
- `IsOptional`
- `PackageFlags`
- `PackageFlags2`
- `HasWin32alacarte`
- `HasFullTrust`
- `ExternalLocation`
- `PackageSourceUri`
- `PackageDisplayName`

### Microsoft-Windows-AppXDeployment-Server / EventID: 412

- `PackageFullName`
- `ErrorCode`

### Microsoft-Windows-AppXDeployment-Server / EventID: 603

- `DeploymentOperation`
- `Path`
- `Flags`
- `FlagsHigh`
- `CallingProcess`
- `ExternalLocation`

### Microsoft-Windows-AppXDeployment-Server / EventID: 854

- `Path`

<!-- event-fields:end -->
