# product: gcp, service: google_workspace.admin

```yaml
logsource:
    product: gcp
    service: google_workspace.admin
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Description](#description)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Description

Administrative events of Google Workspace, with the settings that were changed.

## Points of Attention

- A setting change is described by `setting_name` and by its new value in `new_value`.

## Fields

The rules of this log source use the following field names:

- `eventName`
- `eventService`
- `new_value`
- `setting_name`
