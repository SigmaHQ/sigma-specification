# product: macos, service: endpointsecurity

```yaml
logsource:
    product: macos
    service: endpointsecurity
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
  - [Process](#process)
  - [User and Group](#user-and-group)
  - [File](#file)
  - [Code Signature](#code-signature)
  - [Process Injection and Access](#process-injection-and-access)
  - [Unix and macOS Specific](#unix-and-macos-specific)

<!-- mdformat-toc end -->

## Description

Apple Endpoint Security Framework (ESF) events, collected with `eslogger` or Elastic Defend. ESF is the telemetry API of macOS, see the [Apple documentation](https://developer.apple.com/documentation/endpointsecurity).

## Telemetry

The framework has no event log channel: a collector subscribes to it and receives the events in real time. Every event carries the type of the event it reports, and the `category` attribute selects the event types a rule matches.

| Category          | Event type                                                                                           |
| ----------------- | ---------------------------------------------------------------------------------------------------- |
| process_creation  | 9 (ES_EVENT_TYPE_NOTIFY_EXEC)                                                                        |
| file_event        | 13 (ES_EVENT_TYPE_NOTIFY_CREATE), 19 (ES_EVENT_TYPE_NOTIFY_UNLINK), 21 (ES_EVENT_TYPE_NOTIFY_RENAME) |
| file_create       | 13 (ES_EVENT_TYPE_NOTIFY_CREATE)                                                                     |
| file_delete       | 19 (ES_EVENT_TYPE_NOTIFY_UNLINK)                                                                     |
| file_rename       | 21 (ES_EVENT_TYPE_NOTIFY_RENAME)                                                                     |
| authentication    | 111 (ES_EVENT_TYPE_NOTIFY_AUTHENTICATION)                                                            |
| process_injection | 64 (ES_EVENT_TYPE_NOTIFY_PTRACE)                                                                     |
| process_access    | 64 (ES_EVENT_TYPE_NOTIFY_PTRACE)                                                                     |
| driver_load       | 17 (ES_EVENT_TYPE_NOTIFY_KEXT_LOAD), 18 (ES_EVENT_TYPE_NOTIFY_KEXT_UNLOAD)                           |

The event types of the framework:

| Event type | Apple constant                      | Event                        |
| ---------- | ----------------------------------- | ---------------------------- |
| 9          | ES_EVENT_TYPE_NOTIFY_EXEC           | Process execution            |
| 11         | ES_EVENT_TYPE_NOTIFY_FORK           | Process fork                 |
| 13         | ES_EVENT_TYPE_NOTIFY_CREATE         | File creation                |
| 17         | ES_EVENT_TYPE_NOTIFY_KEXT_LOAD      | Kernel extension load        |
| 18         | ES_EVENT_TYPE_NOTIFY_KEXT_UNLOAD    | Kernel extension unload      |
| 19         | ES_EVENT_TYPE_NOTIFY_UNLINK         | File deletion                |
| 20         | ES_EVENT_TYPE_NOTIFY_MPROTECT       | Memory protection change     |
| 21         | ES_EVENT_TYPE_NOTIFY_RENAME         | File rename                  |
| 22         | ES_EVENT_TYPE_NOTIFY_MOUNT          | Filesystem mount             |
| 24         | ES_EVENT_TYPE_NOTIFY_SETUID         | Set user ID                  |
| 25         | ES_EVENT_TYPE_NOTIFY_SETGID         | Set group ID                 |
| 27         | ES_EVENT_TYPE_NOTIFY_SIGNAL         | Process signal               |
| 64         | ES_EVENT_TYPE_NOTIFY_PTRACE         | Process trace (debug/inject) |
| 65         | ES_EVENT_TYPE_NOTIFY_XPC_CONNECT    | XPC connection               |
| 111        | ES_EVENT_TYPE_NOTIFY_AUTHENTICATION | Authentication event         |

## Points of Attention

- Subscribing to the framework requires root privileges, the collector runs as root on the host.
- The framework streams the events to the collector while it runs, it doesn't keep an event log on the host. The historical events can't be read back, the collector has to forward them to the log source it writes to.
- The fields of the process creation events that the framework shares with the other macOS collectors are documented in the [process creation](./macos_process_creation.md) page.

## Fields

### Process

| Field Name        | Example Value             | Comment                          |
| ----------------- | ------------------------- | -------------------------------- |
| CommandLine       | /usr/bin/curl -o file url | Full command line with arguments |
| CurrentDirectory  | /Users/admin              | Process working directory        |
| Image             | /usr/bin/curl             | Process executable path          |
| ParentCommandLine | /bin/bash -l              | Parent process command line      |
| ParentImage       | /bin/bash                 | Parent process executable path   |
| ParentProcessId   | 1234                      | Parent process ID                |
| ParentProcessName | bash                      | Parent process name              |
| ProcessId         | 12345                     | Process ID                       |
| ProcessName       | curl                      | Process name, without the path   |

### User and Group

The framework reports the real and the effective identifiers separately, which the generic macOS collectors don't.

| Field Name    | Example Value | Comment                          |
| ------------- | ------------- | -------------------------------- |
| GroupId       | 20            | Effective group ID (egid)        |
| RealGroupId   | 20            | Real group ID (rgid)             |
| RealUser      | admin         | Real username                    |
| RealUserId    | 501           | Real user ID (ruid)              |
| TargetGroup   | wheel         | Target group name, setgid events |
| TargetGroupId | 0             | Target group ID, setgid events   |
| TargetUser    | root          | Target username, setuid events   |
| TargetUserId  | 0             | Target user ID, setuid events    |
| User          | admin         | Effective username               |
| UserId        | 501           | Effective user ID (euid)         |

### File

| Field Name          | Example Value                     | Comment                              |
| ------------------- | --------------------------------- | ------------------------------------ |
| DestinationFilename | /tmp/renamed.txt                  | Destination file path, rename events |
| FileDirectory       | /Library/LaunchDaemons            | File directory                       |
| FileName            | evil.plist                        | File name, without the path          |
| SourceFilename      | /tmp/original.txt                 | Source file path, rename events      |
| TargetFilename      | /Library/LaunchDaemons/evil.plist | Target file path                     |

### Code Signature

| Field Name      | Example Value    | Comment                            |
| --------------- | ---------------- | ---------------------------------- |
| SignatureStatus | valid            | Code signature verification status |
| Signed          | true             | Whether the binary is signed       |
| SigningID       | com.apple.Safari | macOS code signing identifier      |
| TeamID          | ABCDE12345       | Apple Developer Team ID            |

### Process Injection and Access

| Field Name        | Example Value     | Comment                             |
| ----------------- | ----------------- | ----------------------------------- |
| SourceImage       | /usr/bin/lldb     | Injecting or accessing process path |
| SourceProcessId   | 1234              | Injecting or accessing process ID   |
| TargetImage       | /Applications/App | Target process executable path      |
| TargetProcessGUID | {guid}            | Target process entity ID            |
| TargetProcessId   | 5678              | Target process ID                   |
| TargetProcessName | App               | Target process name                 |

### Unix and macOS Specific

| Field Name       | Example Value   | Comment                                           |
| ---------------- | --------------- | ------------------------------------------------- |
| KextIdentifier   | com.vendor.kext | Kernel extension bundle ID, event types 17 and 18 |
| MemoryProtection | rwx             | Memory protection flags, event type 20            |
| PtraceRequest    | PT_ATTACH       | Ptrace request type, event type 64                |
| SignalNumber     | 9 (SIGKILL)     | Unix signal number, event type 27                 |
| XpcServiceName   | com.apple.svc   | macOS XPC service name, event type 65             |
