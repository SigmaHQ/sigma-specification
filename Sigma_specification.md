# Sigma specification <!-- omit in toc -->

THIS IS A WORK IN PROGRESS DO NOT USE IT

- Version 2.0.0
- Planned release date 2023/07/01

Take a look at [breaking changes](V2_breaking_changes.md)

# Summary

- [Summary](#summary)
- [Yaml File](#yaml-file)
  - [Filename](#filename)
  - [Data](#data)
- [Structure](#structure)
  - [Rx YAML](#rx-yaml)
- [Components](#components)
  - [Title](#title)
    - [Rule Identification](#rule-identification)
  - [Schema (optional)](#schema-optional)
  - [Taxonomy (optional)](#taxonomy-optional)
  - [Status (optional)](#status-optional)
  - [Description (optional)](#description-optional)
  - [License (optional)](#license-optional)
  - [Author (optional)](#author-optional)
  - [References (optional)](#references-optional)
  - [Date (optional)](#date-optional)
  - [Modified (optional)](#modified-optional)
  - [Log Source](#log-source)
  - [Detection](#detection)
    - [Search-Identifier](#search-identifier)
    - [General](#general)
    - [String Wildcard](#string-wildcard)
    - [Escaping](#escaping)
    - [Lists](#lists)
    - [Maps](#maps)
    - [Field Usage](#field-usage)
    - [Special Field Values](#special-field-values)
    - [Value Modifiers](#value-modifiers)
      - [Modifier Types](#modifier-types)
  - [Condition](#condition)
  - [Fields](#fields)
  - [FalsePositives](#falsepositives)
  - [Level](#level)
  - [Tags](#tags)
  - [Placeholders](#placeholders)
    - [Standard Placeholders](#standard-placeholders)
- [Rule Correlation](#rule-correlation)
- [Global filter](#global-filter)
- [History](#history)

# Yaml File

## Filename

To keep the file names interoperable use the following:

- Length between 10 and 70 characters
- All characters of the filename should be in lowercase
- No special characters only letters (a-z) and digits (0-9)
- Use `_` instead of a space
- Use `.yml` as a file extension

example:

- lnx_auditd_change_file_time_attr.yml
- web_cve_2022_33891_spark_shell_command_injection.yml
- sysmon_file_block_exe.yml

## Data

The rule files are written in [yaml format](https://yaml.org/spec/1.2.2/)
To keep the rules interoperable use:

- UTF-8
- LF for the line break (the Windows native editor uses CR-LF)
- Indentation of 4 spaces
- Lowercase keys (e.g. title, id, etc.)
- Single quotes `'` for strings and numeric values don't use any quotes (if the string contains a single quote, double quotes may be used instead)

Simple Sigma example

```yaml
title: Whoami Execution
description: Detects a whoami.exe execution
references:
      - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
author: Florian Roth
date: 2019/10/23
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'C:\Windows\System32\whoami.exe'
    condition: selection
level: high
```

# Structure

The rules consist of a few required sections and several optional ones.

```yaml
title
id [optional]
related [optional]
   - type {type-identifier}
     id {rule-id}
schema [optional]
taxonomy [optional]
status [optional]
description [optional]
references [optional]
author [optional]
date [optional]
modified [optional]
logsource
   category [optional]
   product [optional]
   service [optional]
   definition [optional]
   ...
detection
   {search-identifier} [optional]
      {string-list} [optional]
      {map-list} [optional]
      {field: value} [optional]
   ...
   condition
fields [optional]
falsepositives [optional]
level [optional]
tags [optional]
...
[arbitrary custom fields]
```

## Rx YAML

The schema is defined in [sigma-schema.rx.yml](sigma-schema.rx.yml)

# Components

## Title

**Attribute:** title

A brief title for the rule that should contain what the rule is supposed to detect (max. 256 characters)

### Rule Identification

**Attributes:** id, related

Sigma rules should be identified by a globally unique identifier in the *id* attribute. For this
purpose randomly generated UUIDs (version 4) are recommended but not mandatory. An example for this
is:

```yml
title: Test rule
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
```

/// 
it's confusing , so think somethink like:
It is better to write a rule with a new id for the following reasons:
///
Rule identifiers can and should change for the following reasons:

* Major changes in the rule. E.g. a different rule logic.
* Derivation of a new rule from an existing or refinement of a rule in a way that both are kept
  active.
* Merge of rules.

To be able to keep track of the relationships between detections, Sigma rules may also contain
references to related rule identifiers in the *related* attribute. This allows to define common
relationships between detections as follows:

```yml
related:
  - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
    type: derived
  - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
    type: obsoletes
```

Currently the following types are defined:

* derived: The rule was derived from the referred rule or rules, which may remain active.
* obsoletes: The rule obsoletes the referred rule or rules, which aren't used anymore.
* merged: The rule was merged from the referred rules. The rules may still exist and are in use.
* renamed: The rule had previously the referred identifier or identifiers but was renamed for whatever
  reason, e.g. from a private naming scheme to UUIDs, to resolve collisions etc. It's not
  expected that a rule with this id exists anymore.
* similar: Use to relate similar rules to each other (e.g. same detection content applied to different log sources, rule that is a modified version of another rule with a different level)

## Schema (optional)

**Attribute:** schema

This is the version of the specification used in the rule.

This will allow us to quickly know if the converter or software can use the rule without any problems
The possible values are 
  - `1.0`
  - `2.0`
When the field is missing, the default value is `1.0`

## Taxonomy (optional)

**Attribute:** taxonomy

Defines the taxonomy used in the Sigma rule. A taxonomy can define:

* field names, example: `process_command_line` instead of `CommandLine`.
* field values, example: a field `image_file_name` that only contains a file name like `example.exe` and is transformed into `ImageFile: *\\example.exe`.
* logsource names, example: `category: ProcessCreation` instead of `category: process_creation`

used in the Sigma rule. The Default taxonomy is "sigma" and can be ommited. A custom taxonomy must be handled by the used tool
or transformed into the default taxonomy.

More information in [Appendix Taxonomy](appendix_taxonomy.md)

## Status (optional)

**Attribute:** status

Declares the status of the rule:

- stable: the rule is considered as stable and may be used in production systems or dashboards.
- test: an almost stable rule that possibly could require some fine tuning.
- experimental: an experimental rule that could lead to false positives results or be noisy, but could also identify interesting
  events.
- deprecated: the rule is replaced or covered by another one. The link is established by the `related` field.
- unsupported: the rule cannot be use in its current state (special correlation log, home-made fields)

## Description (optional)

**Attribute:** description

A short description of the rule and the malicious activity that can be detected (max. 65,535 characters)

## License (optional)

**Attribute:** license

License of the rule according the [SPDX ID specification](https://spdx.org/ids).

## Author (optional)

**Attribute**: author

Creator of the rule. (can be a name, nickname, twitter handle...etc)

## References (optional)

**Attribute**: reference

References to the source that the rule was derived from. These could be blog articles, technical papers, presentations or even tweets.

## Date (optional)

**Attribute**: date

Creation date of the rule. Use the format YYYY/MM/DD or YYYY-MM-DD

## Modified (optional)

**Attribute**: modified

*Last* modification date of the rule. Use the format YYYY/MM/DD or YYYY-MM-DD
Reasons to change the modified date:
* changed title
* changed detection section
* changed level
* changed logsource (rare)

## Log Source

**Attribute**: logsource

This section describes the log data on which the detection is meant to be applied to.
It describes the log source, the platform, the application and the type that is required in the detection.

It consists of three attributes that are evaluated automatically by the converters and an arbitrary number of optional elements.
We recommend using a "definition" value in cases in which further explanation is necessary.

* category - examples: firewall, web, antivirus
* product - examples: windows, apache, check point fw1
* service - examples: sshd, applocker

The "category" value is used to select all log files written by a certain group of products, like firewalls or web server logs.
The automatic converter will use the keyword as a selector for multiple indices.

The "product" value is used to select all log outputs of a certain product, e.g. all Windows Eventlog types including "Security", "System", "Application" and the new log types like "AppLocker" and "Windows Defender".

Use the "service" value to select only a subset of a product's logs, like the "sshd" on Linux or the "Security" Eventlog on Windows systems.

The "definition" can be used to describe the log source, including some information on the log verbosity level or configurations that have to be applied. It is not automatically evaluated by the converters but gives useful information to readers on how to configure the source to provide the necessary events used in the detection.

You can use the values of 'category, 'product' and 'service' to point the converters to a certain index. You could define in the configuration files that the category 'firewall' converts to `( index=fw1* OR index=asa* )` during Splunk search conversion or the product 'windows' converts to `"_index":"logstash-windows*"` in Elasticsearch queries.

Instead of referring to particular services, generic log sources may be used, e.g.:

```yml
category: process_creation
product: windows
```

Instead of definition of multiple rules for Sysmon, Windows Security Auditing and possible product-specific rules.

More information in [appendix_taxonomy.md](appendix_taxonomy.md) and [SigmaHQ docuementaiton](https://github.com/SigmaHQ/sigma/blob/master/documentation/README.md)

## Detection

**Attribute**: detection

A set of search-identifiers that represent properties of searches on log data.

### Search-Identifier

A definition that can consist of two different data structures - lists and maps.

### General

* All values are treated as case-insensitive strings
* You can use wildcard characters `*` and `?` in strings (see also escaping section below)
* Regular expressions are case-sensitive by default
* You don't have to escape characters except the string quotation marks `'`

### String Wildcard

Wildcards are used when part of the text is random.
You can use :

* `?` to replace a single mandatory character
* `*` to replace an unbounded length wildcard

example  :

* `progA.exe or progB.exe or ...` will be `prog?.exe`
* `antivirus_V1.exe or antivirus_V21.2.1.exe or ...` will be `antivirus_V*.exe`

Sigma has special modifiers to facilitate the search of unbounded strings

* `*something` see [endswith modifier](#value-modifiers)
* `something*` see [startswith modifier](#value-modifiers)
* `*something*` see [contains modifier](#value-modifiers)

### Escaping

The backslash character `\` is used for escaping of wildcards `*` and `?` as well as the backslash character itself. Escaping of the backslash is necessary if it is followed by a wildcard depending on the desired result.

Summarized, these are the following possibilities:

* Plain backslash not followed by a wildcard can be expressed as single `\` or double backslash `\\`. For simplicity reasons the single notation is recommended.
* A wildcard has to be escaped to be handled as a plain character: `\*`
* The backslash before a wildcard has to be escaped to handle the value as a backslash followed by a wildcard: `\\*`
* Three backslashes are necessary to escape both, the backslash and the wildcard and handle them as plain values: `\\\*`
* Three or four backslashes are handled as double backslash. Four is recommended for consistency reasons: `\\\\` results in the plain value `\\`.

### Lists

Lists can contain:

* strings that are applied to the full log message and are linked with a logical 'OR'.
* maps (see below). All map items of a list are logically linked with 'OR'.

Example for list of strings: Matches on 'EvilService' **or** 'svchost.exe -n evil'

```yml
detection:
  keywords:
    - 'EVILSERVICE'
    - 'svchost.exe -n evil'
```

Example for list of maps:

```yml
detection:
  selection:
    - Image|endswith: '\\example.exe'
    - Description|contains: 'Test executable'
```

The example above matches an image value ending with `example.exe` or an executable with a description containing the string `Test executable`

### Maps

Maps (or dictionaries) consist of key/value pairs, in which the key is a field in the log data and the value is a string or integer value. All elements of a map are joined with a logical 'AND'.

Examples:

Matches on Eventlog 'Security' **and** ( Event ID 517 **or** Event ID 1102 )

```yml
detection:
  selection:
    EventLog: Security
    EventID:
      - 517
      - 1102
condition: selection
```

Matches on Eventlog 'Security' **and** Event ID 4679 **and** TicketOptions 0x40810000 **and** TicketEncryption 0x17

```yml
detection:
   selection:
      EventLog: Security
      EventID: 4769
      TicketOptions: '0x40810000'
      TicketEncryption: '0x17'
condition: selection
```

### Field Usage

1. For fields with existing field-mappings, use the mapped field name.

Examples from [the generic config `tools\config\generic\windows-audit.yml`](https://github.com/SigmaHQ/sigma/blob/master/tools/config/generic/windows-audit.yml#L23-L28) (e.g. use `Image` over `NewProcessName`):

```yml
fieldmappings:
    Image: NewProcessName
    ParentImage: ParentProcessName
    Details: NewValue
    ParentCommandLine: ProcessCommandLine
    LogonId: SubjectLogonId
```

2. For new or rarely used fields, use them as they appear in the log source and strip all spaces. (This means: Only, if the field is not already mapped to another field name.) On Windows event log sources, use the field names of the details view as the general view might contain localized field names.

Examples:
* `New Value` -> `NewValue`
* `SAM User Account` -> `SAMUserAccount`

3. Clarification on Windows events from the EventViewer:
    1. Some fields are defined as attributes of the XML tags (in the `<System>` header of the events). The tag and attribute names have to be linked with an underscore character '_'.
    2. In the `<EventData>` body of the event the field name is given by the `Name` attribute of the `Data` tag.

Examples i:

* `<Provider Name="Service Control Manager" Guid="[...]" EventSourceName="[...]" />` will be `Provider_Name`
* ` <Execution ProcessID="788" ThreadID="792" />` will be `Execution_ProcessID`

Examples ii:

* `<Data Name="User">NT AUTHORITY\SYSTEM</Data>` will be `User`
* `<Data Name="ServiceName">MpKsl4eaa0a76</Data>` will be `ServiceName`

### Special Field Values

There are special field values that can be used.

* An empty value is defined with `''`
* A null value is defined with `null`

*OBSOLETE*: An arbitrary value except null or empty cannot be defined with `not null` anymore

The application of these values depends on the target SIEM system.

To get an expression that say `not null` you have to create another selection and negate it in the condition.

Example:

```yml
detection:
   selection:
      EventID: 4738
   filter:
      PasswordLastSet: null
condition:
   selection and not filter
```

### Value Modifiers

The values contained in Sigma rules can be modified by *value modifiers*. Value modifiers are
appended after the field name with a pipe character `|` as separator and can also be chained, e.g.
`fieldname|mod1|mod2: value`. The value modifiers are applied in the given order to the value.

#### Modifier Types

There are two types of value modifiers:

* *Transformation modifiers* transform values into different values, like the two Base64 modifiers
  mentioned below. Furthermore, this type of modifiers is also able to change the logical operation
  between values. Transformation modifiers are generally backend-agnostic. Meaning: you can use them
  with any backend.
* *Type modifiers* change the type of a value. The value itself might also be changed by such a
  modifier, but the main purpose is to tell the backend that a value should be handled differently
  by the backend, e.g. it should be treated as regular expression when the *re* modifier is used.
  Type modifiers must be supported by the backend.

Generally, value modifiers work on single values and value lists. A value might also expand into
multiple values.

[List of modifiers](appendix_modifer.md)

## Condition

**Attribute**: condition

The condition is the most complex part of the specification and will be subject to change over time and arising requirements. In the first release it will support the following expressions.

- Logical AND/OR

  `keywords1 or keywords2`

- 1/all of them

  Logical OR (`1 of them`) or AND (`all of them`) across all defined search identifiers. The search identifiers
  themselves are logically linked with their default behaviour for maps (AND) and lists (OR).

  The usage of `all of them` is discouraged, as it prevents the possibility of downstream users of a rule to generically filter unwanted matches. See `all of {search-identifier-pattern}` in the next section as the preferred method.

  Example: `1 of them` means that one of the defined search identifiers must appear.

- 1/all of search-identifier-pattern

  Same as *1/all of them*, but restricted to matching search identifiers. Matching is done with * wildcards (any number of characters) at arbitrary positions in the pattern.

  Examples:
  - `all of selection*`
  - `1 of selection* and keywords`
  - `1 of selection* and not 1 of filter*`

- Negation with 'not'

  `keywords and not filters`

- Brackets

  `selection1 and (keywords1 or keywords2)`

Operator Precedence (least to most binding)

- or
- and
- not
- x of search-identifier
- ( expression )

If multiple conditions are given, they are logically linked with OR.

## Fields

**Attribute**: fields

A list of log fields that could be interesting in further analysis of the event and should be displayed to the analyst.

## FalsePositives

**Attribute**: falsepositives

A list of known false positives that may occur.

## Level

**Attribute**: level

The level field contains one of five string values. It describes the criticality of a triggered rule. While `low` and `medium` level events have an informative character, events with `high` and `critical` level should lead to immediate reviews by security analysts.

- `informational`: Rule is intended for enrichment of events, e.g. by tagging them. No case or alerting should be triggered by such rules because it is expected that a huge amount of events will match these rules.
- `low`: Notable event but rarely an incident. Low rated events can be relevant in high numbers or combination with others. Immediate reaction shouldn't be necessary, but a regular review is recommended.
- `medium`: Relevant event that should be reviewed manually on a more frequent basis.
- `high`: Relevant event that should trigger an internal alert and requires a prompt review.
- `critical`: Highly relevant event that indicates an incident. Critical events should be reviewed immediately.

## Tags

**Attribute**: tags

A Sigma rule can be categorised with tags. Tags should generally follow this syntax:

* Character set: lower-case letters, numerals, underscores and hyphens
* no spaces
* Tags are namespaced, the dot is used as separator. e.g. *attack.t1234* refers to technique 1234 in the namespace *attack*; Namespaces may also be nested
* Keep tags short, e.g. numeric identifiers instead of long sentences
* Feel free to send pull request or issues with proposals for new tags

[More information about tags](appendix_tags.md)

## Placeholders

Placeholders are used as values that get their final meaning at conversion or usage time of the rule. This can be, but is not restricted to:

* Replacement of placeholders with a single, multiple or-linked values or patterns. Example: the placeholder `%Servers%` is replaced with
  the pattern `srv*` because servers are named so in the target environment.
* Replacement of placeholders with a query expression. Example: replacement of `%servers%` with a lookup expression `LOOKUP(field, servers)`
  that looks up the value of `field` in a lookup table `servers`.
* Conducting lookups in tables or APIs while matching the Sigma rule that contains placeholders.

From Sigma 1.1 placeholders are only handled if the *expand* modifier is applied to the value containing the placeholder.
A plain percent character can be used by escaping it with a backslash. Examples:

* `field: %name%` handles `%name%` as literal value.
* `field|expand: %name%` handles `%name%` as placeholder.
* `field|expand: \%plain%name%` handles `%plain` as plain value and `%name%` as placeholder.

Placeholders must be handled appropriately by a tool that uses Sigma rules. If the tool isn't able to handle placeholders, it must reject the rule.

### Standard Placeholders

The following standard placeholders should be used:

* `%Administrators%`: Administrative user accounts
* `%JumpServers%`: Server systems used as jump servers
* `%Workstations%`: Workstation systems
* `%Servers%`: Server systems
* `%DomainControllers%`: Domain controller systems

Custom placeholders can be defined as required.

# Rule Correlation

// Need to add brief text //

See [Appendix Mega Rules](appendix_mega_rules.md)

# Global filter

// Need to add brief text //

See [Appendix Mega Rules](appendix_mega_rules.md)

# History

* 2023/07/01 Specification V2.0.0
  * Start a new life
