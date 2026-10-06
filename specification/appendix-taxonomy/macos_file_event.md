# product: macos, category: file_event

```yaml
logsource:
    product: macos
    category: file_event
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

The event source isn't declared by the rules. The field names follow the Sysmon naming, so the events are read through a collector that maps the macOS events onto that schema.

## Points of Attention

- The rules don't set the `definition` attribute and the rules repository has no logsource guide for this category, so the requirements of the macOS collection aren't documented yet.

## Fields

| Field Name     | Example Value                   | Comment                       |
| -------------- | ------------------------------- | ----------------------------- |
| TargetFilename | /etc/emond.d/rules/custom.plist | Full path of the created file |
