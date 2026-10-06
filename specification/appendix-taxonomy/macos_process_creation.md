# product: macos, category: process_creation

```yaml
logsource:
    product: macos
    category: process_creation
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

| Field Name  | Example Value                                    | Comment                               |
| ----------- | ------------------------------------------------ | ------------------------------------- |
| CommandLine | /usr/bin/osascript -e 'tell app "System Events"' | Command line of the process           |
| Image       | /usr/bin/osascript                               | Full path of the process image        |
| ParentImage | /sbin/launchd                                    | Full path of the parent process image |
