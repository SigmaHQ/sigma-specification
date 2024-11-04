# Sigma Correlation Rules Specification <!-- omit in toc -->

The following document defines the standardized correlation that can be used in Sigma rules.

* Version 2.0.2
* Release date 2024-11-01

- [Introduction](#introduction)
  - [Compatibility](#compatibility)
  - [Expression of Relationships In The Condition of Sigma Rules](#expression-of-relationships-in-the-condition-of-sigma-rules)
  - [Type of Correlation rules](#type-of-correlation-rules)
- [Correlation rules](#correlation-rules)
  - [File Structure](#file-structure)
    - [YAML File](#yaml-file)
    - [Schema](#schema)
    - [Syntax](#syntax)
  - [Components](#components)
    - [Title](#title)
    - [Identification](#identification)
    - [Status](#status)
    - [Description](#description)
    - [Author](#author)
    - [References](#references)
    - [Date](#date)
    - [Modified](#modified)
    - [Correlation section](#correlation-section)
      - [Correlation type](#correlation-type)
      - [Related rules](#related-rules)
      - [Aliases](#aliases)
      - [Grouping](#grouping)
      - [Time Selection](#time-selection)
      - [Condition](#condition)
    - [FalsePositives](#falsepositives)
    - [Level](#level)
    - [Generate](#generate)
  - [Correlation Types](#correlation-types)
    - [Event Count (event\_count)](#event-count-event_count)
    - [Value Count (value\_count)](#value-count-value_count)
    - [Temporal Proximity (temporal)](#temporal-proximity-temporal)
    - [Ordered Temporal Proximity (temporal\_ordered)](#ordered-temporal-proximity-temporal_ordered)
  - [Field Name Aliases](#field-name-aliases)
    - [Field Name Aliases Example](#field-name-aliases-example)
- [Examples](#examples)
  - [Failed Logins Followed by Successful Login](#failed-logins-followed-by-successful-login)
- [History](#history)

## Introduction

Sometimes you need more advanced searches than simple selections.
For this purpose, you can use meta-rules that correlate multiple Sigma rules.

### Compatibility

When generating a backend specific query, Sigma correlations might exceed the capabilities of that targeted backend. \
Or the Sigma correlation might require a feature that is only supported partially by the target backend. \
Therefore target-specific restrictions should be handled in a way that ensures that the generated queries do not create results that:

* Could be misinterpreted
* Change the intention/context in which the rule matches
* Cause a huge amount of false positives
* Cause false negatives

An error must be raised by the conversion backend if it would generate a query from a rule which contains a feature that is not supported but specified as must. Examples are:

* The target system can aggregate an occurrence count but cannot apply a condition to filter the aggregated counts.
* The target system is not able to aggregate an occurrence count according to the given grouping criteria.
* It is only possible to generate a query up to an intermediate correlation rule of a chain.

The conversion backend should issue a warning to raise the user’s awareness about restrictions for aspects specified as "should". \
Examples are:

* Temporal relationships are recognized, but the order of the events cannot be recognized by the target system. This could cause false positives by differently ordered events.
* Temporal relationships are only recognized within static time boundaries, e.g. a `timespan` of 1h only matches if all events appear within a full hour, but not if some events appear in the previous and another event in the current hour. This could cause false negatives.

### Expression of Relationships In The Condition of Sigma Rules

This was the first approach defined in Sigma with aggregations and the near operator and is now obsolete. \
Sigma correlations are not based on this approach for the following reasons:

* The coupling of rules describing singular events and relationships between multiple events is inconsistent, as the rule writer must decide which rule contains the relationship definition in case of temporal relationships.
* It was inflexible because one Sigma rule refers exactly to one log source, which restricts the expression of relationships to events from the same log source.
* One of the goals of Sigma rules was to keep the condition logic simple. Especially the specification of temporal relationships can get quite complex in a query expression. Specifying correlation chains adds further complexity.
* The pipe syntax sometimes caused the rule contributors to consider it as a Splunk query or another target system-specific query language. Expressing these relationships in a “Sigmaish” way should not cause these associations.

### Type of Correlation rules

The purpose is to cover a detection like:

* X invalid login alerts on a unique host.
* Invalid login alert on the same host but from X remote.
* Alert A, B and C in the same `timespan`.

## Correlation rules

The rules in a multi-document YAML that build a correlation rule are not producing individual, independent queries. They are used as a tool to define more complex constructs out of basic Sigma detections. Therefore only the outermost correlation rule may define meta information such as status, level, date or anything else.

### File Structure

#### YAML File

To keep the file names interoperable use the following:

* Length between 10 and 70 characters
* Lowercase
* No special characters, only letters (a-z) and digits (0-9)
* Use `_` instead of a space
* Use `.yml` as a file extension

As a best practice use the prefix `mr_`.

#### Schema

[Sigma Correlation Rules JSON Schema](/json-schema/sigma-correlation-rules-schema.json)

#### Syntax

A Sigma correlation is a dedicated YAML document.
Like Sigma rules , correlation rules have a title and a unique id to identify them.

### Components

#### Title

**Attribute:** title

**Use:** mandatory

A brief title for the rule that should contain what the rule is supposed to detect (max. 256 characters)

#### Identification

**Attribute:** id

**Use:** optional

Sigma meta-rules should be identified by a globally unique identifier in the *id* attribute.
For this purpose randomly generated UUIDs (version 4) are recommended but not mandatory.

An example for this is:

```yml
title: login brute force
id: 0e95725d-7320-415d-80f7-004da920fc11
```

#### Status

**Attribute:** status

**Use:** optional

Declares the status of the rule:

- `stable`: the rule is considered as stable and may be used in production systems or dashboards.
- `test`: a mostly stable rule that could require some slight adjustments depending on the environement.
- `experimental`: an experimental rule that could lead to false positives results or be noisy, but could also identify interesting
  events.
- `deprecated`: the rule is replaced or covered by another one. The link is established by the `related` field.
- `unsupported`: the rule cannot be use in its current state (old correlation format, custom fields)

#### Description

**Attribute:** description

**Use:** optional

A short description of the rule and the malicious activity that can be detected (max. 65,535 characters)

#### Author

**Attribute**: author

**Use:** optional

Creator of the rule. (can be a name, nickname, twitter handle...etc)

#### References

**Attribute**: reference

**Use:** optional

References to the source that the rule was derived from. \
These could be blog articles, technical papers, presentations or even tweets.

#### Date

**Attribute**: date

**Use:** optional

Creation date of the meta rule. \
Use the ISO 8601 date with separator format: `YYYY-MM-DD`

#### Modified

**Attribute**: modified

**Use:** optional

*Last* modification date of the meta rule. \
Use the ISO 8601 date with separator format : `YYYY-MM-DD`

#### Correlation section

##### Correlation type

**Attribute:** type

**Use:** mandatory

Allowed values:

* event_count
* value_count
* temporal
* temporal_ordered

##### Related rules

**Attribute:** rules

**Use:** mandatory

Refers to one or multiple Sigma or Correlations rules.
Allowing the user to chain multiple correlations together.
A rule can be referred to by the `id` or `name` of a Sigma rule.

`name` is a per correlation **unique** human-readable name that improves the readability of correlation rules.
In this case, the tool must be able to manage the name-to-id translation automatically and the referenced rule name has to be defined in the respective rule.

```yaml
title: login brute force
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
  rules:
    - 5638f7c0-ac70-491d-8465-2a65075e0d86 # ID of the low firewall rule for action: block
    - firewall_block  # The internal tools have a lookup table to the correct rule `id` by `name`
```

##### Aliases

**Attribute:** aliases

**Use:** optional

defines field name aliases that are applied to correlated Sigma rules.
The defined aliases can then be defined in `group-by` and allows aggregation across different fields in different event types.

See the example in the chapter [Field Name Aliases](#field-name-aliases) to get a better understanding.

##### Grouping

**Attribute:** group-by

**Use:** mandatory

optionally defines one or multiple fields which should be treated as separate event occurrence scope. Examples:

* count events by user
* temporal proximity must occur on one system by the same user

When you use multiple fields they are linked by an **AND**.

for example, if we want to group by the unique "name/domain" pair:
```yaml
group-by:
    - TargetUserName
    - TargetDomainName
```

##### Time Selection

**Attribute:** timespan

**Use:** mandatory

defines a time period in which the correlation should be applied.
The following format must be used: `number + letter (in lowercase)`

* Xs seconds
* Xm minutes
* Xh hours
* Xd days

example for 1h30 : `timespan: 90m`

##### Condition

**Attribute:** condition

**Use:** mandatory

The condition defines when a correlation matches:

* for an *event_count* correlation it defines the event count that must appear within the given time frame to match.
* for a *value_count* correlation it defines the count of distinct values contained in the field specified in the
  mandatory *field* attribute.
* For a *temporal* or *temporal_ordered* correlation it specified the count of different event types (Sigma rules
  matching) in the given time frame.

It is a map of exactly one condition criterion:

* `gt`: The count must be greater than the given value
* `gte`: The count must be greater than or equal the given value
* `lt`: The count must be lesser than the given value
* `lte`: The count must be lesser than or equal the given value
* `eq`: The count must be equal the given value

Example:
```yaml
condition:
    gte: 100
```

To define a range, you can use the conjunction 'AND' in the mapping.

Example "101 to 200":
```yaml
condition:
    gt: 100
    lte: 200
```

If you need more complex constructs, you can always chain correlation rules together.
See the examples at the far bottom, for more details.

#### FalsePositives

**Attribute**: falsepositives

**Use:** optional

A list of known false positives that may occur.

#### Level

**Attribute:**  level

**Use:** optional

defines a severity level adjustment if the correlation matches.
This allows to give single event hits a low or informational severity and increasing this to higher levels in case of correlating appearances of events.

#### Generate

**Attribute:** generate

**Use:** optional

defines if the rules referred from the correlation rule should be converted
as stand-alone rules or if only the correlation query should be generated (default).

### Correlation Types

#### Event Count (event_count)

Counts events occurring in the given time frame specified by the referred Sigma rule or rules.
The resulting query must count events for each group specified by group-by separately.
The condition finally defines how many events must occur to generate a search hit.

Requires :
 - `group-by`
 - `timespan`
 - `condition`

Simple example : More than or equal 100 failed login attempts to a destination host in an hour:

```yaml
title: Many failed logins
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: event_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    group-by:
        - ComputerName
    timespan: 1h
    condition:
        gte: 100
```

#### Value Count (value_count)

Counts values in a field defined by `field`.
The resulting query must count field values separately for each group specified by group-by.
The condition finally defines how many values must occur to generate a search hit.

Requires:
  - `group-by`
  - `timespan`
  - `condition`
  - `field` in condition section.

Simple example : Failed logon attempts with more than 100 different user accounts per source and destination at a day:

```yaml
title: Failed login
id: 0e95725d-7320-415d-80f7-004da920fc12
correlation:
    type: value_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    group-by:
        - ComputerName
        - WorkstationName
    timespan: 1d
    condition:
        field: User
        gte: 100
```

#### Temporal Proximity (temporal)

All events defined by the rules referred by the rule field must occur in the time frame defined by timespan.
The values of fields defined in group-by must all have the same value (e.g. the same host or user).

The time frame should not be restricted to boundaries if this is not required by the given backend.

Requires:
  - `rules`
  - `group-by`
  - `timespan`

Simple example : Reconnaissance commands defined in three Sigma rules are invoked in arbitrary order within 5 minutes on a system by the same user:

```yaml
correlation:
    type: temporal
    rules:
        - recon_cmd_a
        - recon_cmd_b
        - recon_cmd_c
    group-by:
        - ComputerName
        - User
    timespan: 5m
```

#### Ordered Temporal Proximity (temporal_ordered)

The *temporal_ordered* correlation type behaves like *temporal* and requires in addition that the events appear in the
order provided in the *rule* attribute.

Requires:
  - `rules`
  - `group-by`
  - `timespan`

Example: many failed logins as defined above are followed by a successful login by of the same user account within 1 hour:

```yaml
correlation:
    type: temporal_ordered
    rules:
        - many_failed_logins
        - successful_login
    group-by:
        - User
    timespan: 1h
```

Note:
Even if the rule many_failed_logins groups by the "ComputerName" field, the correlation rule only uses its own `group-by` "User".

### Field Name Aliases

Sometimes correlation of values in the same fields is not sufficient. E.g. a correlation rule might require to aggregate events that appear from a source address in one event and the same address as destination in another event. A Sigma correlation rule can contain an `aliases` attribute that defines an alias for different field names in events matched by different Sigma rules. The alias field names can then be referenced in `group-by` attributes and are resolved to their respective field names.

Aliases are defined as follows:

```
aliases:
  <alias name>:
    <Sigma rule name>: <source field name in event matched by Sigma rule>
[...]
```

The field names referenced in aliases must not necessarily appear in the Sigma rules, but in the events matched by the Sigma rules.

`<Sigma rule name>` is the name given by the `name` attribute. \
The `name` attribute is optional in general, but has to be defined, if you want to use `aliases`.

#### Field Name Aliases Example

The following correlation rule defines field name aliases `internal_ip` and `remote_ip` that are used in the `group-by` attribute. \
The `internal_ip` alias references the field `destination.ip` in the events matched by the Sigma rule `internal_error` and `source.ip` in the events matched by the Sigma rule `new_network_connection`. \
The correlation rule then only matches if the events appear with the same address in the respective fields of the events matching the referenced Sigma rules.

Rule internal_error

```yaml
name: internal_error
detection:
    selection:
        http.response.status_code: 500
    condition: selection
```

Rule new_network_connection

```yaml
name: new_network_connection
detection:
    selection:
        event.category: network
        event.type: connection
        event.outcome: success
    condition: selection
```

The correlation rule
```yaml
title: —
id: —
correlation:
    type: temporal
    rules:
        - internal_error
        - new_network_connection
    group-by:
        - internal_ip
        - remote_ip
    timespan: 10s
    aliases:
        internal_ip:
            internal_error: destination.ip
            new_network_connection: source.ip
        remote_ip:
            internal_error: source.ip
            new_network_connection: destination.ip
```

## Examples

This section gives complete examples in order to make it easier for people new to Sigma to get started and for showcasing new features of the Sigma standard. Use them as a blueprint for your own ideas.

### Failed Logins Followed by Successful Login

The following Correlation describes a use case in which an attacker successfully performs a brute-force attack. This example helps in showcasing some highlights:

* You can use YAMLs multi document feature (`---`) to have everything grouped together in one file
* Rules can be referenced in a human-friendly way using their unique `name`.
* Correlations can be chained to express more complex use cases

```yml
title: Correlation - Multiple Failed Logins Followed by Successful Login
id: b180ead8-d58f-40b2-ae54-c8940995b9b6
status: experimental
description: Detects multiple failed logins by a single user followed by a successful login of that user
references:
    - https://reference.com
author: Florian Roth (Nextron Systems)
date: 2023-06-16
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_login
        - successful_login
    group-by:
        - User
    timespan: 10m
falsepositives:
    - Unlikely
level: high
---
title: Multiple failed logons
id: a8418a5a-5fc4-46b5-b23b-6c73beb19d41
description: Detects multiple failed logins within a certain amount of time
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 10
---
title: Single failed login
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 529
            - 4625
    condition: selection
---
title: Successful login
id: 4d0a2c83-c62c-4ed4-b475-c7e23a9269b8
description: Detects a successful login
name: successful_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 4624
    condition: selection
```

## History

* 2024-11-01 Specification V2.0.2
  * add Requires field for temporal rules
* 2024-09-03 Specification V2.0.1
  * add missing `status` and `falsepositives`
* 2024-08-08 Specification v2.0.0
