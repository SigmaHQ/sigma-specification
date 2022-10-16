# Sigma specification <!-- omit in toc -->

* Version 1.0.0
* Release date 2022/09/18

History:
* 2022/09/18 Specification V1.0.0
  * Initial formalisation from the sigma wiki
* 2017 Sigma creation
  
# Summary

- [Summary](#summary)
- [Yaml File](#yaml-file)
  - [Filename](#filename)
  - [Data](#data)
- [Structure](#structure)
  - [Schema](#schema)
    - [Rx YAML](#rx-yaml)
    - [Image](#image)
  - [Components](#components)
    - [Title](#title)
    - [Rule Identification](#rule-identification)
    - [Status (optional)](#status-optional)
    - [Description (optional)](#description-optional)
    - [License (optional)](#license-optional)
    - [Author (optional)](#author-optional)
    - [References (optional)](#references-optional)
    - [Log Source](#log-source)
    - [Detection](#detection)
      - [Search-Identifier](#search-identifier)
      - [General](#general)
      - [Escaping](#escaping)
      - [Lists](#lists)
      - [Maps](#maps)
      - [Field Usage](#field-usage)
      - [Special Field Values](#special-field-values)
      - [Value Modifiers](#value-modifiers)
        - [Modifier Types](#modifier-types)
        - [Currently Available Modifiers](#currently-available-modifiers)
          - [Transformations](#transformations)
          - [Types](#types)
    - [Condition](#condition)
    - [Fields](#fields)
    - [FalsePositives](#falsepositives)
    - [Level](#level)
    - [Tags](#tags)
    - [Placeholders](#placeholders)
      - [Examples for placeholders](#examples-for-placeholders)
      - [Examples for conversions](#examples-for-conversions)
  - [Rule Collections](#rule-collections)
    - [Example](#example)

# Yaml File

## Filename

To keep the file names interoperable use the following:

- Length between 10 and 70 characters 
- Lowercase
- No special characters only letters (a-z) and digits (0-9)
- Use `_` instead of space
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
status [optional]
description [optional]
author [optional]
references [optional]
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

## Schema

### Rx YAML

```yaml
type: //rec
required:
    title:
        type: //str
        length:
            min: 1
            max: 256
    logsource:
        type: //rec
        optional:
            category: //str
            product: //str
            service: //str
            definition: //str
    detection:
        type: //rec
        required:
            condition:
                type: //any
                of:
                    - type: //str
                    - type: //arr
                      contents: //str
                      length:
                          min: 2
        rest:
            type: //any
            of:
                - type: //arr
                  of:
                      - type: //str
                      - type: //map
                        values:
                            type: //any
                            of:
                                - type: //str
                                - type: //arr
                                  contents: //str
                                  length:
                                    min: 2
                - type: //map
                  values:
                      type: //any
                      of:
                          - type: //str
                          - type: //arr
                            contents: //str
                            length:
                                min: 2
optional:
    status:
        type: //any
        of:
            - type: //str
              value: stable
            - type: //str
              value: test
            - type: //str
              value: experimental
            - type: //str
              value: deprecated
            - type: //str
              value: unsupported
    description: //str
    author: //str
    references:
        type: //arr
        contents: //str
    fields:
        type: //arr
        contents: //str
    falsepositives:
        type: //any
        of:
            - type: //str
            - type: //arr
              contents: //str
              length:
                  min: 2
    level:
        type: //any
        of:
            - type: //str
              value: informational
            - type: //str
              value: low
            - type: //str
              value: medium
            - type: //str
              value: high
            - type: //str
              value: critical
rest: //any
```

###  Image

![sigma_schema](https://github.com/SigmaHQ/sigma-specification/images/Sigma_Schema.png)

##  Components

###  Title

**Attribute:** title

A brief title for the rule that should contain what the rules is supposed to detect (max. 256 characters)

### Rule Identification

**Attributes:** id, related

Sigma rules should be identified by a globally unique identifier in the *id* attribute. For this
purpose randomly generated UUIDs (version 4) are recommended but not mandatory. An example for this
is:

```yml
title: Test rule
id: 929a690e-bef0-4204-a928-ef5e620d6fcc
```

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
* merged: The rule was merged from the referred rules. The rules may be still existing and in use.
* renamed: The rule had previously the referred identifier or identifiers but was renamed for whatever
  reason, e.g. from a private naming scheme to UUIDs, to resolve collisions etc. It's not
  expected that a rule with this id exists anymore.
* similar: Use to relate similar rules to each other (e.g. same detection content applied to different log sources, rule that is a modified version of another rule with a different level)

### Status (optional)

**Attribute:** status

Declares the status of the rule:

- stable: the rule is considered as stable and may be used in production systems or dashboards.
- test: an almost stable rule that possibly could require some fine tuning.
- experimental: an experimental rule that could lead to false positives results or be noisy, but could also identify interesting
  events.
- deprecated: the rule is replace or cover by another one. The link is made by the `related` field.
- unsupported: the rule can not be use in its current state (special correlation log, home-made fields)


### Description (optional)

**Attribute:** description

A short description of the rule and the malicious activity that can be detected (max. 65,535 characters)

### License (optional)

**Attribute:** license

License of the rule according the [SPDX ID specification](https://spdx.org/ids).

### Author (optional)

**Attribute**: author

Creator of the rule. (can be a name, nickname, twitter handle...etc)

### References (optional)

**Attribute**: reference

References to the source that the rule was derived from. These could be blog articles, technical papers, presentations or even tweets.

### Log Source

**Attribute**: logsource

This section describes the log data on which the detection is meant to be applied to. It describes the log source, the platform, the application and the type that is required in the detection.

It consists of three attributes that are evaluated automatically by the converters and an arbitrary number of optional elements. We recommend using a "definition" value in cases in which further explanation is necessary.

* category - examples: firewall, web, antivirus
* product - examples: windows, apache, check point fw1
* service - examples: sshd, applocker

The "category" value is used to select all log files written by a certain group of products, like firewalls or web server logs. The automatic converter will use the keyword as a selector for multiple indices.

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

### Detection

**Attribute**: detection

A set of search-identifiers that represent properties of searches on log data.

#### Search-Identifier

A definition that can consist of two different data structures - lists and maps.

#### General

* All values are treated as case-insensitive strings
* You can use wildcard characters `*` and `?` in strings (see also escaping section below)
* Regular expressions are case-sensitive by default
* You don't have to escape characters except the string quotation marks `'`

#### Escaping

The backslash character `\` is used for escaping of wildcards `*` and `?` as well as the backslash character itself. Escaping of the backslash is necessary if it is followed by a wildcard depending on the desired result.

Summarized, there are the following possibilities:

* Plain backslash not followed by a wildcard can be expressed as single `\` or double backslash `\\`. For simplicity reasons the single notation is recommended.
* A wildcard has to be escaped to handle it as a plain character: `\*`
* The backslash before a wildcard has to be escaped to handle the value as a backslash followed by a wildcard: `\\*`
* Three backslashes are necessary to escape both, the backslash and the wildcard and handle them as plain values: `\\\*`
* Three or four backslashes are handled as double backslash. Four a recommended for consistency reasons: `\\\\` results in the plain value `\\`.

#### Lists

Lists can contain:

* strings that are applied to the full log message and are linked with a logical 'OR'.
* maps (see below). All map items of a list are logically linked with 'OR'.

Example for list of strings: Matches on 'EvilService' **or** 'svchost.exe -n evil'

```yml
detection:
  keywords:
    - EVILSERVICE
    - svchost.exe -n evil
```

Example for list of maps:

```yml
detection:
  selection:
    - Image|endswith: \\example.exe
    - Description|contains: Test executable
```

Matches an image file `example.exe` or an executable whose description contains the string `Test executable`

#### Maps

Maps (or dictionaries) consist of key/value pairs, in which the key is a field in the log data and the value a string or integer value. All elements of a map are joined with a logical 'AND'.

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

#### Field Usage

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

2. For new or rarely used fields, use them as they appear in the log source and strip all spaces. (That means: Only, if the field is not already mapped to another field name.) On Windows event log sources, use the field names of the details view as the general view might contain localized field names.

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

#### Special Field Values

There are special field values that can be used.

* An empty value is defined with `''`
* A null value is defined with `null`

OBSOLETE: An arbitrary value except null or empty cannot be defined with `not null` anymore

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

#### Value Modifiers

The values contained in Sigma rules can be modified by *value modifiers*. Value modifiers are
appended after the field name with a pipe character `|` as separator and can also be chained, e.g.
`fieldname|mod1|mod2: value`. The value modifiers are applied in the given order to the value.

##### Modifier Types

There are two types of value modifiers:

* *Transformation modifiers* transform values into different values, like the two Base64 modifiers
  mentioned above. Furthermore, this type of modifier is also able to change the logical operation
  between values. Transformation modifiers are generally backend-agnostic. Means: you can use them
  with any backend.
* *Type modifiers* change the type of a value. The value itself might also be changed by such a
  modifier, but the main purpose is to tell the backend that a value should be handled differently
  by the backend, e.g. it should be treated as regular expression when the *re* modifier is used.
  Type modifiers must be supported by the backend.

Generally, value modifiers work on single values and value lists. A value might also expand into
multiple values.

##### Currently Available Modifiers

###### Transformations

* `contains`: puts `*` wildcards around the values, such that the value is matched anywhere in the
  field.
* `all`: Normally, lists of values were linked with *OR* in the generated query. This modifier
  changes
  this to *AND*. This is useful if you want to express a command line invocation with different
  parameters where the order may vary and removes the need for some cumbersome workarounds.
  
  Single item values are not allowed to have an `all` modifier as some back-ends cannot support it.
  If you use it as a workaround to duplicate a field in a selection, use a new selection instead.
* `base64`: The value is encoded with Base64.
* `base64offset`: If a value might appear somewhere in a base64-encoded value the representation
  might change depending on the position in the overall value. There are three variants for shifts
  by zero to two bytes and except the first and last byte the encoded values have a static part in
  the middle that can be recognized.
* `endswith`: The value is expected at the end of the field's content (replaces e.g. '*\cmd.exe')
* `startswith`: The value is expected at the beginning of the field's content. (replaces e.g. 'adm*')
* `utf16le`: transforms value to UTF16-LE encoding, e.g. `cmd` > `63 00 6d 00 64 00` (only used in combination with base64 modifiers)
* `utf16be`: transforms value to UTF16-BE encoding, e.g. `cmd` > `00 63 00 6d 00 64` (only used in combination with base64 modifiers)
* `wide`: alias for `utf16le` modifier
* `utf16`: prepends a [byte order mark](https://en.wikipedia.org/wiki/Byte_order_mark) and encodes UTF16, e.g. `cmd` > `FF FE 63 00 6d 00 64 00` (only used in combination with base64 modifiers)
* `windash`: Add a new variant where all `-` occurrences are replaced with `/`. The original variant is also kept unchanged.

###### Types

* `re`: value is handled as regular expression by backends. Currently, this is only supported by
  the Elasticsearch query string backend (*es-qs*). Further (like Splunk) are planned or have
  to be implemented by contributors with access to the target systems.

### Condition

**Attribute**: condition

The condition is the most complex part of the specification and will be subject to change over time and arising requirements. In the first release it will support the following expressions.

- Logical AND/OR

  `keywords1 or keywords2`

- 1/all of search-identifier

  Same as just 'keywords' if keywords are defined in a list. X may be:

  - 1 (logical or across alternatives)
  - all (logical and across alternatives)

  Example: `all of keywords` means that all items of the list keywords must appear, instead of the default behaviour of any of the listed items.

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

- Pipe (deprecated)

  `search_expression | aggregation_expression`

  A pipe indicates that the result of *search_expression* is aggregated by *aggregation_expression* and possibly
  compared with a value.

  The first expression must be a search expression that is followed by an aggregation expression with a condition.

  Aggregations in the condition are deprecated and will be replaced with [Sigma correlations](https://github.com/SigmaHQ/sigma/wiki/Specification:-Sigma-Correlations).

- Aggregation expression (deprecated, see [Sigma Correlations specification](https://github.com/SigmaHQ/sigma/wiki/Specification:-Sigma-Correlations) for future plans)

  agg-function(agg-field) [ by group-field ] comparison-op value

  agg-function may be:

  - count
  - min
  - max
  - avg
  - sum

  All aggregation functions except count require a field name as parameter. The count aggregation counts all matching events if no field name is given. With field name it counts the distinct values in this field.

  Example: `count(UserName) by SourceWorkstation > 3`

  This comparison counts distinct user names grouped by SourceWorkstations.

- Near aggregation expression (deprecated, see [Sigma Correlations specification](https://github.com/SigmaHQ/sigma/wiki/Specification:-Sigma-Correlations) for future plans)

  near *search-id-1* [ [ and *search-id-2* | and not *search-id-3* ] ... ]

  This expression generates (if supported by the target system and backend) a query that recognizes *search_expression* (primary event) if the given conditions are or are not in the temporal context of the primary event within the given time frame.

Operator Precedence (least to most binding)

- |
- or
- and
- not
- x of search-identifier
- ( expression )

If multiple conditions are given, they are logically linked with OR.

### Fields

**Attribute**: fields

A list of log fields that could be interesting in further analysis of the event and should be displayed to the analyst.

### FalsePositives

**Attribute**: falsepositives

A list of known false positives that may occur.

### Level

**Attribute**: level

The level field contains one of five string values. It describes the criticality of a triggered rule. While `low` and `medium` level events have an informative character, events with `high` and `critical` level should lead to immediate reviews by security analysts.

- `informational`: Rule is intended for enrichment of events, e.g. by tagging them. No case or alerting should be triggered by such rules because it is expected that a huge amount of events will match these rules.
- `low`: Notable event but rarely an incident. Low rated events can be relevant in high numbers or combination with others. Immediate reaction shouldn't be necessary, but a regular review is recommended.
- `medium`: Relevant event that should be reviewed manually on a more frequent basis.
- `high`: Relevant event that should trigger an internal alert and requires a prompt review.
- `critical`: Highly relevant event that indicates an incident. Critical events should be reviewed immediately.

### Tags

**Attribute**: tags

A Sigma rule can be categorised with tags. Tags should generally follow this syntax:

* Character set: lower-case letters, underscores and hyphens
* no spaces
* Tags are namespaced, the dot is used as separator. e.g. *attack.t1234* refers to technique 1234 in the namespace *attack*; Namespaces may also be nested
* Keep tags short, e.g. numeric identifiers instead of long sentences
* If applicable, use [predefined tags](./Tags). Feel free to send pull request or issues with proposals for new tags

### Placeholders

Placeholders can be used to select a set of elements that can be expanded during conversion.
Placeholders map a an identifier to a user defined value that can be set in config files for an
automatic replacement during conversion runs. Placeholders are meaningful identifiers that users can
easily expand themselves.

#### Examples for placeholders

* `%Administrators%` - Administrative user accounts
* `%JumpServers%` - Server systems used as jump servers

Some SIEM systems allow using so-called "tags" or "search macros" in queries and can integrate Sigma rules with placeholders directly. Others expand the placeholders values to wildcard strings or regular expressions.

#### Examples for conversions

Splunk

* `AccountName: %Administrators%` convert to `tag=Administrators`

Elastic Search 

* `SourceWorkstation: %JumpServers%` convert to `"SourceWorkstation": SRV110[12]`

## Rule Collections

A file may contain multiple YAML documents. These can be complete Sigma rules or *action documents*. A YAML document is handled as action document if the `action` attribute on the top level is set to:

* `global`: Defines YAML content that is merged in all following YAML rule documents in this file. Multiple *global* action documents are accumulated.
** Use case: define metadata and rule parts that are common across all Sigma rules of a collection.
* `reset`: Reset global YAML content defined by *global* action documents.
* `repeat`: Repeat generation of previous rule document with merged data from this YAML document.
** Use case: Small modifications of previously generated rule.

### Example
A common use case is the definition of multiple Sigma rules for similar events like Windows Security EventID 4688 and Sysmon EventID 1. Both are created for process execution events. A Sigma rule collection for this scenario could contain three documents:

1. A global action document that defines common metadata and detection indicators
2. A rule that defines Windows Security log source and EventID 4688
3. A rule that defines Windows Sysmon log source and EventID 1

Alternative solution could be:

1. A global action document that defines common metadata.
2. The Security/4688 rule with all event details.
3. A repeat action document that replaces the logsource and EventID from the rule defined in 2.
