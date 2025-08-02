# Sigma Rules Specification

- Version 2.0.0
- Release date 2024-08-08

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [File Structure](#file-structure)
  - [Yaml File](#yaml-file)
  - [Schema](#schema)
- [Components](#components)
  - [Title](#title)
  - [Identification](#identification)
  - [Name](#name)
  - [Taxonomy](#taxonomy)
  - [Status](#status)
  - [Description](#description)
  - [License](#license)
  - [Author](#author)
  - [References](#references)
  - [Date](#date)
  - [Modified](#modified)
  - [LogSource](#logsource)
  - [Detection](#detection)
    - [Search-Identifier](#search-identifier)
    - [General](#general)
    - [String Wildcard](#string-wildcard)
    - [Escape Character](#escape-character)
    - [Lists](#lists)
    - [Maps](#maps)
    - [Field Usage](#field-usage)
    - [Special Field Values](#special-field-values)
    - [Field Existence](#field-existence)
    - [Value Modifiers](#value-modifiers)
      - [Modifier Types](#modifier-types)
    - [Placeholders](#placeholders)
      - [Standard Placeholders](#standard-placeholders)
    - [Keywords search](#keywords-search)
  - [Condition](#condition)
  - [Fields](#fields)
  - [FalsePositives](#falsepositives)
  - [Level](#level)
  - [Tags](#tags)
  - [Scope](#scope)
- [Rule Correlation](#rule-correlation)
- [Sigma Filters](#sigma-filters)
- [History](#history)

<!-- mdformat-toc end -->

## File Structure

The rules consist of a few required sections and several optional ones.

```yaml
title
id [optional]
name [optional]
related [optional]
   - type {type-identifier}
     id {rule-id}
taxonomy [optional]
status [optional]
description [optional]
license [optional]
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
scope [optional]
...
[arbitrary custom fields]
```

### Yaml File

The rule files are written in [yaml format](https://yaml.org/spec/1.2.2/)
In order to keep the rules interoperable use the following:

- UTF-8 encoding.
- LF for the line break (the Windows native editor uses CR-LF).
- Indentation of 4 spaces.
- Lowercase keys (e.g. title, id, etc.).
- Strings values use Single quotes `'` . If the string contains a single quote, double quotes may be used instead.
- Numeric values don't use any quotes.

Below is a simple Sigma rule example:

```yaml
title: Whoami Execution
description: Detects a whoami.exe execution
references:
      - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
author: Florian Roth
date: 2019-10-23
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'C:\Windows\System32\whoami.exe'
    condition: selection
level: high
```

To keep the file names interoperable use the following:

- Length between 10 and 70 characters
- All characters of the filename should be in lowercase
- No special characters only letters (a-z) and digits (0-9)
- Use `_` instead of a space
- Use `.yml` as a file extension

example:

- `lnx_auditd_change_file_time_attr.yml`
- `web_cve_2022_33891_spark_shell_command_injection.yml`
- `sysmon_file_block_exe.yml`

### Schema

The Json schema is defined in [sigma-detection-rule-schema.json](../json-schema/sigma-detection-rule-schema.json). Check it out for additional details on the required fields, their types and other information.

## Components

### Title

**Attribute:** title

**Use:** mandatory

A brief title for the rule that should contain what the rule is supposed to detect (max. 256 characters)

### Identification

**Attributes:** id, related

**Use:** optional

Sigma rules should be identified by a globally unique identifier in the *id* attribute. \
For this purpose randomly generated UUIDs (version 4) is used. \
An example for this is:

```yml
title: Test rule
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
```

It is better to write a rule with a new id for the following reasons:

- Major changes in the rule. E.g. a different rule logic.
- Derivation of a new rule from an existing or refinement of a rule in a way that both are kept active.
- Merging of rules.

To be able to keep track of the relationships between detections, Sigma rules may also contain
references to related rule identifiers in the *related* attribute. \
This allows to define common relationships between detections as follows:

```yml
related:
  - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
    type: derived
  - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
    type: obsolete
```

Currently the following types are defined:

- `correlation`: The rule is used in the referred correlation rule.
- `derived`: The rule was derived from the referred rule or rules, which may remain active.
- `obsolete`: The rule obsoletes the referred rule or rules, which aren't used anymore.
- `merged`: The rule was merged from the referred rules. The rules may still exist and are in use.
- `renamed`: The rule had previously the referred identifier or identifiers but was renamed for whatever
  reason, e.g. from a private naming scheme to UUIDs, to resolve collisions etc. It's not
  expected that a rule with this id exists anymore.
- `similar`: Use to relate similar rules to each other (e.g. same detection content applied to different log sources, rule that is a modified version of another rule with a different level)

### Name

**Attribute:** name

**Use:** optional

`name` is a **unique** human-readable name that can be used instead of the *id* as a reference in correlation rules. \
The goal is to improve the readability of correlation rules.

### Taxonomy

**Attribute:** taxonomy

**Use:** optional

Defines the taxonomy used in the Sigma rule. A taxonomy can define:

- field names, example: `process_command_line` instead of `CommandLine`.
- field values, example: a field `image_file_name` that only contains a file name like `example.exe` and is transformed into `ImageFile: *\\example.exe`.
- logsource names, example: `category: ProcessCreation` instead of `category: process_creation`

The Default taxonomy is `sigma`. A custom taxonomy must be handled by the used tool or transformed into the default taxonomy.

More information on the default taxonomy can be found in the [Sigma Taxonomy Appendix](sigma-appendix-taxonomy.md) file.

### Status

**Attribute:** status

**Use:** optional

Declares the status of the rule:

- `stable`: the rule is considered as stable and may be used in production systems or dashboards.
- `test`: a mostly stable rule that could require some slight adjustments depending on the environment.
- `experimental`: an experimental rule that could lead to false positives results or be noisy, but could also identify interesting
  events.
- `deprecated`: the rule is replaced or covered by another one. The link is established by the `related` field.
- `unsupported`: the rule cannot be use in its current state (old correlation format, custom fields)

### Description

**Attribute:** description

**Use:** optional

A short and accurate description of the rule and the malicious or suspicious activity that can be detected (max. 65,535 characters)

### License

**Attribute:** license

**Use:** optional

License of the rule according the [SPDX ID specification](https://spdx.org/ids).

### Author

**Attribute**: author

**Use:** optional

Creator of the rule. (can be a name, nickname, twitter handle...etc) \
If there is more than one, they are separated by a comma.

### References

**Attribute**: reference

**Use:** optional

References to the sources that the rule was derived from. \
These could be blog articles, technical papers, presentations or even tweets.

### Date

**Attribute**: date

**Use:** optional

Creation date of the rule. \
Use the ISO 8601 date with separator format : YYYY-MM-DD

### Modified

**Attribute**: modified

**Use:** optional

*Last* modification date of the rule. \
Use the ISO 8601 date with separator format : YYYY-MM-DD

Reasons to change the modified date:

- changed title
- changed detection section
- changed level
- changed logsource (rare)
- changed status to `deprecated`

### LogSource

**Attribute**: logsource

**Use:** mandatory

This section describes the log data on which the detection is meant to be applied to. \
It describes the log source, the platform, the application and the type that is required in the detection.

It consists of three attributes that are evaluated automatically by the converters and an arbitrary number of optional elements. \
We recommend using a "definition" value in cases in which further explanation is necessary.

- category - examples: firewall, web, antivirus
- product - examples: windows, apache, check point fw1
- service - examples: sshd, applocker

The `category` value is used to select all log files written of a logical group. \
This may cover one or more sources of information depending on the system. \
e.g. "antivirus" for the scan result, "webserver" for the web access logs.

The `product` value is used to select all log outputs of a certain product. \
It can be as generic as an operating system or the name of a particular software package. \
e.g. "windows" will include "Security", "System", "Application" and the other like "AppLocker" and "Windows Defender"...

The `service` value is used to select a more specific subset of logs. \
e.g. "sshd" on Linux or the "Security" Eventlog on Windows systems.

The `definition` can be used to describe the log source, including some information on the log verbosity level or configurations that have to be applied. \
It is not automatically evaluated by the converters but gives useful information to readers on how to configure the source to provide the necessary events used in the detection.

The `category`, `product` and `service` can be used alone or in any combination. \
Their values are in **lower case** and spaces are replaced by a `_` , characters `.` and `-` are allowed.

- Windows Channel "System" -> `service: system`
- "Process Creation" -> `category: process_creation`
- Cloud OneLogin events -> `service: onelogin.events`
- Windows Channel "Microsoft-Windows-Windows Firewall With Advanced Security" -> `service: firewall-as`

You can use the values of `category`, `product` and `service` to point the converters to a certain index. \
In the configuration files, it can be defined that the category `firewall` converts to `( index=fw1* OR index=asa* )` during Splunk search conversion or the product `windows` converts to `"_index":"logstash-windows*"` in Elasticsearch queries.

The advantages of this abstract approach is that it does not limit the rule to a specific telemetry source.

Instead creating multiple rules for the different telemetry sources such as `Sysmon`, `Microsoft-Windows-Security-Auditing`, `Microsoft-Windows-Kernel-Process` and all the other possible product-specific sources, a generic log source may be used. \
e.g.:

```yml
category: process_creation
product: windows
```

More details can be found in the [Sigma Taxonomy Appendix](sigma-appendix-taxonomy.md) file, and [SigmaHQ Logsource Guides](https://github.com/SigmaHQ/sigma/tree/master/documentation/logsource-guides)

### Detection

**Attribute**: detection

**Use:** mandatory

A set of search-identifiers that represent properties of searches on log data.

#### Search-Identifier

A definition that can consist of two different data structures - lists and maps.

#### General

- All values are treated as case-insensitive strings.
- You can use wildcard characters `*` and `?` in strings (see also the [escape character](#escape-character) section below).
- Regular expressions are case-sensitive by default.
- You don't have to escape characters except the string quotation marks `'`.

#### String Wildcard

Wildcards are used when part of the text is random.
You can use :

- `?` to replace a single mandatory character.
- `*` to replace an unbounded length wildcard.

example:

- `progA.exe or progB.exe or ...` will be `prog?.exe`
- `antivirus_V1.exe or antivirus_V21.2.1.exe or ...` will be `antivirus_V*.exe`

Sigma has special modifiers to facilitate the search of unbounded strings

- `*something` see [endswith modifier](#value-modifiers).
- `something*` see [startswith modifier](#value-modifiers).
- `*something*` see [contains modifier](#value-modifiers).

#### Escape Character

The backslash character `\` is used for escaping of wildcards `*` and `?` as well as the backslash character itself. Escaping of the backslash is necessary if it is followed by a wildcard depending on the desired result.

Summarized, these are the following possibilities:

- Plain backslash not followed by a wildcard can be expressed as single `\` or double backslash `\\`. For simplicity reasons the single notation is recommended.
- A wildcard has to be escaped to be handled as a plain character. eg: `\*`, `\?`.
- The backslash before a wildcard has to be escaped to handle the value as a backslash followed by a wildcard: `\\*`.
- Three backslashes are necessary to escape both, the backslash and the wildcard and handle them as plain values: `\\\*`.
- Three or four backslashes are handled as double backslash. Four is recommended for consistency reasons: `\\\\` results in the plain value `\\`.

#### Lists

Lists can contain:

- strings that are applied to the full log message and are linked with a logical 'OR'.
- maps (see below). All map items of a list are logically linked with 'OR'.

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

The example above matches an image value ending with `example.exe` **or** an executable with a description containing the string `Test executable`.

#### Maps

Maps (or dictionaries) consist of key/value pairs, in which the key is a field in the log data and the value is a string or integer value. All elements of a map are joined with a logical 'AND'.

Examples:

The example below, matches on EventLog 'Security' **and** ( Event ID 517 **or** Event ID 1102 )

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

#### Field Usage

1. For fields with existing field-mappings, use the mapped field name.

Below is an example mapping `sigma` taxonomy name to built-in windows events:

```yml
fieldmappings:
    Image: NewProcessName
    ParentImage: ParentProcessName
    Details: NewValue
    ParentCommandLine: ProcessCommandLine
    LogonId: SubjectLogonId
```

2. For new or rarely used fields, use them as they appear in the log source and strip all spaces. (This means: Only, if the field is not already mapped to another field name.) On Windows event log sources, use the field names of the details view as the general view might contain localized field names.

Example:

- `New Value` -> `NewValue`
- `SAM User Account` -> `SAMUserAccount`

3. Clarification on Windows events from the EventViewer:
   1. Some fields are defined as attributes of the XML tags (in the `<System>` header of the events). The tag and attribute names have to be linked with an underscore character '\_'.
   1. In the `<EventData>` body of the event the field name is given by the `Name` attribute of the `Data` tag.

Examples i:

- `<Provider Name="Service Control Manager" Guid="[...]" EventSourceName="[...]" />` will be `Provider_Name`
- ` <Execution ProcessID="788" ThreadID="792" />` will be `Execution_ProcessID`

Examples ii:

- `<Data Name="User">NT AUTHORITY\SYSTEM</Data>` will be `User`
- `<Data Name="ServiceName">MpKsl4eaa0a76</Data>` will be `ServiceName`

#### Special Field Values

There are special field values that can be used.

- An empty value is defined with `''`
- A null value is defined with `null`

The application of these values depends on the target SIEM system.

In general it is encouraged to take special care of `null` during rule creation. A `not null` construct should be its
own selection and `null` cannot be part of a list of field values.

To get an expression that says `not null` you have to create another selection and negate it in the condition.

Example:

```yml
detection:
    selection:
        EventID: 4738
    filter:
        PasswordLastSet: null
    condition: selection and not filter
```

Also `null` cannot be part of a list of field values as it is its own type and therefore shares no type with any other value.

Valid Example:

```yml
detection:
    selection_main:
        FieldA: 'something'
    selection_empty1:
        FieldB: ''
    selection_empty2:
        FieldB: null
    condition: selection_main and 1 of selection_empty*
```

Invalid Example:

```yml
detection:
    selection_main:
        FieldA: 'something'
        FieldB:
            - ''
            - null
    condition: selection_main
```

#### Field Existence

In some case a field can be optional in the event. You can use the `exists` modifiers to check it.

Example:

```yml
detection:
    selection:
        EventID: 4738
        PasswordLastSet|exists: true
    condition: selection
```

#### Value Modifiers

The values contained in Sigma rules can be modified by *value modifiers*. Value modifiers are
appended after the field name with a pipe character `|` as separator and can also be chained, e.g.
`fieldname|mod1|mod2: value`. The value modifiers are applied in the given order to the value.

##### Modifier Types

There are two types of value modifiers:

- *Transformation modifiers* transform values into different values, like the two Base64 modifiers
  mentioned below. Furthermore, this type of modifiers is also able to change the logical operation
  between values. Transformation modifiers are generally backend-agnostic. Meaning: you can use them
  with any backend.
- *Type modifiers* change the type of a value. The value itself might also be changed by such a
  modifier, but the main purpose is to tell the backend that a value should be handled differently
  by the backend, e.g. it should be treated as regular expression when the *re* modifier is used.
  Type modifiers must be supported by the backend.

Generally, value modifiers work on single values and value lists. A value might also expand into
multiple values.

[List of modifiers](sigma-appendix-modifiers.md)

#### Placeholders

Placeholders are used as values that get their final meaning at conversion or usage time of the rule. This can be, but is not restricted to:

- Replacement of placeholders with a single, multiple or-linked values or patterns. Example: the placeholder `%Servers%` is replaced with
  the pattern `srv*` because servers are named so in the target environment.
- Replacement of placeholders with a query expression. Example: replacement of `%servers%` with a lookup expression `LOOKUP(field, servers)`
  that looks up the value of `field` in a lookup table `servers`.
- Conducting lookups in tables or APIs while matching the Sigma rule that contains placeholders.

From Sigma 1.1 placeholders are only handled if the *expand* modifier is applied to the value containing the placeholder.
A plain percent character can be used by escaping it with a backslash. Examples:

- `field: %name%` handles `%name%` as literal value.
- `field|expand: %name%` handles `%name%` as placeholder.
- `field|expand: \%plain%name%` handles `%plain` as plain value and `%name%` as placeholder.

Placeholders must be handled appropriately by a tool that uses Sigma rules. If the tool isn't able to handle placeholders, it must reject the rule.

##### Standard Placeholders

The following standard placeholders should be used:

- `%Administrators%`: Administrative user accounts
- `%JumpServers%`: Server systems used as jump servers
- `%Workstations%`: Workstation systems
- `%Servers%`: Server systems
- `%DomainControllers%`: Domain controller systems

Custom placeholders can be defined as required.

#### Keywords search

Contrary to the Field Usage, It's a matter of searching for keywords across an entire event. \
They are built by using a list under a search-identifiers.

```yml
detection:
    mimikatz_keywords:
        - 'event::clear'
        - 'event::drop'
    condition: mimikatz_keywords
```

Give : "event::clear" **or** "event::drop"

To have a **and** operator , we use the `'|all':` modifier

```yaml
detection:
    keywords_cmdlet:
        '|all':
            - 'OabVirtualDirectory'
            - ' -ExternalUrl '
    condition: keywords_cmdlet
```

Give : "OabVirtualDirectory" **and** " -ExternalUrl "

Some rules use simply `keywords` as search-identifiers name to facilitate identification.

### Condition

**Attribute**: condition

**Use:** mandatory

The condition is the most complex part of the specification and will be subject to change over time and arising requirements. In the first release it will support the following expressions.

- Logical AND/OR

  `keywords1 or keywords2`

- 1/all of them

  Logical OR (`1 of them`) or AND (`all of them`) across all defined search identifiers not starting with an underscore `_`. The search identifiers
  themselves are logically linked with their default behavior for maps (AND) and lists (OR).

  The usage of `all of them` is discouraged, as it prevents the possibility of downstream users of a rule to generically filter unwanted matches. See `all of {search-identifier-pattern}` in the next section as the preferred method.

  Example: `1 of them` means that one of the defined search identifiers must appear. A search identifier `_example`
  wouldn't be included because detections starting with underscores are excluded by convention.

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

The condition can be a list, in this case, each of them generates a query
They are logically linked with OR.

### Fields

**Attribute**: fields

**Use:** optional

A list of log fields that could be interesting in further analysis of the event and should be displayed to the analyst.

### FalsePositives

**Attribute**: falsepositives

**Use:** optional

A list of known false positives that may occur.

### Level

**Attribute**: level

**Use:** optional

The level field contains one of five string values. It describes the criticality of a triggered rule. While `low` and `medium` level events have an informative character, events with `high` and `critical` level should lead to immediate reviews by security analysts.

- `informational`: Rule is intended for enrichment of events, e.g. by tagging them. No case or alerting should be triggered by such rules because it is expected that a huge amount of events will match these rules.
- `low`: Notable event but rarely an incident. Low rated events can be relevant in high numbers or combination with others. Immediate reaction shouldn't be necessary, but a regular review is recommended.
- `medium`: Relevant event that should be reviewed manually on a more frequent basis.
- `high`: Relevant event that should trigger an internal alert and requires a prompt review.
- `critical`: Highly relevant event that indicates an incident. Critical events should be reviewed immediately. It is used only for cases in which probability borders certainty.

### Tags

**Attribute**: tags

**Use:** optional

A Sigma rule can be categorized with tags. Tags should generally follow this syntax:

- Character set: lower-case letters, numerals, underscores and hyphens
- no spaces
- Tags are namespaced, the dot is used as separator. e.g. *attack.t1234* refers to technique 1234 in the namespace *attack*; Namespaces may also be nested
- Keep tags short, e.g. numeric identifiers instead of long sentences
- Feel free to send pull request or issues with proposals for new tags

[More information about tags](sigma-appendix-tags.md)

### Scope

**Attribute**: scope

**Use:** optional

A list of the intended scopes of the rule. This would allow you to define if a rule is meant to trigger on specific set of types of machines that might have a specific software installed.

For example , if you have a rule for a registry key being set, where the key only exists on windows server installations./
A scope with the value `server` can be added to limit this rule only to Windows Servers.

## Rule Correlation

Correlation allows several events to be linked together. To make it easier to read these corelation rules, they are written in meta-rules.

Check out the [Sigma Correlation Rules Specification](sigma-correlation-rules-specification.md) for more details.

## Sigma Filters

To adapt the rules to the environment, it is sometimes useful to put the same exclusion in several rules. /
Their maintenance can become difficult, with a meta-filter it is possible to write it in a single place.

Check out the [Sigma Filters Specification](sigma-filters-specification.md) for more details.

## History

- 2024-08-08 Specification v2.0.0
- 2023-06-29 Specification v1.0.4
- 2022-12-28 Specification v1.0.3
