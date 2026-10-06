# Taxonomy Page Template

The Sigma taxonomy documents the log sources and the field names that rules shared in the official SigmaHQ repository may use. Every log source has its own page, and this document defines the structure and the formatting that a page follows. The [page skeleton](#page-skeleton) at the end of this document is the starting point of a new page. All the pages are listed in the [Sigma Taxonomy](../sigma-appendix-taxonomy.md) file.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [File Names](#file-names)
- [Page Structure](#page-structure)
- [Description](#description)
- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)
- [Page Skeleton](#page-skeleton)
- [Checklist](#checklist)

<!-- mdformat-toc end -->

## File Names

- A page is named after the log source it documents: `<product>_<value>.md`, like `windows_process_creation.md`, `windows_security.md` or `m365_audit.md`.
- A log source without a `product` attribute is named after its value alone, like `proxy.md`, `antivirus.md` or `apache.md`.
- A log source without a `product` attribute that has a `category` and a `service` attribute is named after both: `<category>_<service>.md`, like `network_connection.md`.
- A log source with a `product` attribute and neither a `category` nor a `service` attribute is named after the product alone, like `linux.md`.
- The file name uses the value of the log source attribute, not the name of the log source in prose.
- `template.md` is this document and isn't a log source page.

## Page Structure

A page consists of:

1. A title that names the attributes of the log source, with the name of the attribute, in the order `product`, `category`, `service`: `# product: windows, category: process_creation`. The heading follows the `logsource` attribute names, like the logsource guides of the rules repository do.
1. A `logsource` block, with the same attributes and the same order, ready to be copied into a rule.
1. The sections that apply to the log source, in the order `## Description`, `## Telemetry`, `## Points of Attention`, `## Fields`. A section without information is left out.

A page doesn't carry a version, a release date or a history, the [Sigma Taxonomy](../sigma-appendix-taxonomy.md) file holds them.

A log source that accepts several values of an attribute is documented on a single page. `product: macos, service: endpointsecurity` accepts nine values of `category`: they are listed in the `## Telemetry` section and the fields they share are listed once in the `## Fields` section.

A log source that is written by several event sources has one subsection per event source, `### Microsoft-Windows-Sysmon` or `### Provider: Microsoft Windows Security Auditing / EventID: 4688` for example. The subsections of `## Telemetry` hold the identifiers of the events of the source, the ones of `## Fields` hold the fields it writes.

## Description

What the log source collects, in one or two sentences. Leave the section out when the value of the `category` or `service` attribute is self-explanatory.

## Telemetry

Where the events are read from, followed by the list of the event identifiers. The section starts with a sentence that names the source of the events, so that a reader knows what has to be collected on the host:

```text
Events read from the Microsoft-Windows-Sysmon/Operational channel, written by Sysmon.

- EventID: 1
```

- `EventID` identifies a Windows event log record, `Channel` the event log channel, `Provider` the ETW provider, `File` the log file of a non-Windows host.
- `EventType` identifies an event of a telemetry API that has no event log channel, like the Endpoint Security Framework of macOS: `- EventType: 9`.
- A single value is written on the bullet of the attribute: `- EventID: 1`.
- Several values are written as a list under the attribute: `- EventIDs:` followed by one bullet per value.
- Leave the section out when the log source isn't tied to an event source.

## Points of Attention

What has to be enabled on the host to receive the events, and the traps of the log source: the audit policy subcategory, the Sysmon configuration, the log level, the fields that are only filled in with a given configuration. One short sentence per point, and each point traceable to where it comes from:

- the `definition` attribute of the rules that use the log source, `Requirements: Script Block Logging must be enabled` for the rules of `rules/windows/powershell`;
- the logsource guide of the rules repository, [`documentation/logsource-guides/windows/category/ps_module.md`](https://github.com/SigmaHQ/sigma/blob/master/documentation/logsource-guides/windows/category/ps_module.md), which holds the complete setup with the audit policy commands and the Sysmon configuration;
- the documentation of the vendor, linked with a URL.

The content of a logsource guide is copied into the page instead of being linked, because the taxonomy has to be readable without the rules repository. Name the guide at the top of the section so that both documents can be compared when one of them changes.

Leave the section out when the event source is enough to collect the log source.

## Fields

The field names of the log source, either as a list or as a table:

- A list when the field is only described by its meaning: `` - `c-uri`: URL requested by the client ``.
- A table with the columns `Field Name`, `Example Value` and `Comment` when an example value helps to identify the field, like the field names of a process creation event.
- Leave the section out when the log source uses the field names of another page.

The fields an event source writes for an event are documented per event identifier, in a subsection of the section:

- The `### <event source> / EventID: <identifier>` heading names the source of the fields and the event, `### Microsoft-Windows-Sysmon / EventID: 1`, like the subsections of `## Telemetry`.
- The subsection holds the payload field names of the event as a list, in the order of the event template.
- The subsections, with the sentence that names where the field names come from, sit between the `<!-- event-fields:start -->` and the `<!-- event-fields:end -->` markers, so that a tool can refresh them without touching the rest of the section.
- Event identifiers the source doesn't document are left out of the section.

The field names of the Windows pages come from the manifests and the provider CSVs of [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources).

## Page Skeleton

````markdown
# product: windows, category: process_creation

```yaml
logsource:
    product: windows
    category: process_creation
```

## Description

<what the log source collects>

## Telemetry

<where the events are read from>

- EventID: 1
- Channel: Microsoft-Windows-Sysmon/Operational

## Points of Attention

- <what has to be enabled on the host, and the traps of the log source>

## Fields

| Field Name  | Example Value                               | Comment |
| ----------- | ------------------------------------------- | ------- |
| Image       | C:\\Program Files\\Google\\Update.exe       |         |
| CommandLine | "C:\\Program Files\\Google\\Update.exe" /ua |         |
````

## Checklist

- The file name is built from the attributes of the `logsource` block of the page.
- The page is listed in the table of its folder in the [Sigma Taxonomy](../sigma-appendix-taxonomy.md) file.
- The change is listed in the history of the [Sigma Taxonomy](../sigma-appendix-taxonomy.md) file, and in `changelog/version-2.1-2.2.md` when it changes the accepted taxonomy.
- The page is formatted with `mdformat`.
