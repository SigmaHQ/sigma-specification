# product: linux, service: auditd

```yaml
logsource:
    product: linux
    service: auditd
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

Events written by the audit daemon to the audit log of the host.

## Points of Attention

- Every rule of the repository declares in its `definition` the audit rules that have to be added to the configuration of auditd for the detection to work, the keys or the system calls to monitor and the key to write them under.
- The event types of the audit log are `SYSCALL`, `PATH`, `EXECVE`, `CWD`, `PROCTITLE` and `SERVICE_STOP`, the rules of the repository match on their fields.

## Fields

The rules of this log source use the following field names:

- `SYSCALL`
- `a0`
- `a1`
- `a2`
- `a3`
- `a4`
- `a5`
- `a6`
- `a7`
- `comm`
- `euid`
- `exe`
- `key`
- `name`
- `nametype`
- `type`
- `unit`
