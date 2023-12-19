# Sigma Correlation <!-- omit in toc -->

The following document defines the standardized correlation that can be used in Sigma rules.

* Version 2.0.0
* Release date 2024/01/01

- [Introduction](#introduction)
  - [Compatibility](#compatibility)
  - [Expression of Relationships In The Condition of Sigma Rules](#expression-of-relationships-in-the-condition-of-sigma-rules)
  - [Type of rules](#type-of-rules)
    - [Correlation rules](#correlation-rules)
    - [Global Filter rules](#global-filter-rules)
- [Correlation rules](#correlation-rules-1)
  - [File Structure](#file-structure)
    - [YAML File](#yaml-file)
    - [Schema](#schema)
    - [Syntax](#syntax)
  - [Components](#components)
    - [Title](#title)
    - [Rule Identification](#rule-identification)
    - [Related rules](#related-rules)
    - [Correlation type](#correlation-type)
    - [Grouping](#grouping)
    - [Values Field Name selection](#values-field-name-selection)
    - [Time Selection](#time-selection)
    - [Condition Selection](#condition-selection)
    - [Level](#level)
    - [Aliases](#aliases)
    - [Generate](#generate)
  - [Metric Conditions](#metric-conditions)
  - [Event Count (event\_count)](#event-count-event_count)
  - [Value Count (value\_count)](#value-count-value_count)
  - [Temporal Proximity (temporal)](#temporal-proximity-temporal)
  - [Ordered Temporal Proximity (temporal\_ordered)](#ordered-temporal-proximity-temporal_ordered)
  - [Field Name Aliases](#field-name-aliases)
    - [Field Name Aliases Example](#field-name-aliases-example)
- [Global Filter](#global-filter)
  - [File Structure](#file-structure-1)
    - [YAML File](#yaml-file-1)
    - [Schema](#schema-1)
    - [Syntax](#syntax-1)
  - [Components](#components-1)
    - [title](#title-1)
    - [action](#action)
    - [Change to Condition](#change-to-condition)
    - [Description](#description)
    - [Log source](#log-source)
    - [filter selection](#filter-selection)
- [Examples](#examples)
  - [Correlation](#correlation)
    - [Failed Logins Followed by Successful Login](#failed-logins-followed-by-successful-login)

# Introduction

Sometimes you need more advanced searches than simple selections.  
For that you can use meta-rules that correlate multiple Sigma rules or filter on existing rules.

## Compatibility

When generating a backend specific query, Sigma correlations might exceed the capabilities of that targeted backend. Or the Sigma correlation might required a feature that is only supported partially by the target backend. Therefore target-specific restrictions should be handled in a way that ensures that the generated queries do not create results that:

* Could be misinterpreted
* Change the intention/context in which the rule matches
* Cause a huge amount of false positives
* Cause false negatives

An error must be raised by the conversion backend if it would generate a query from a rule which contains a feature that is not supported but specified as must. Examples are:

* The target system can aggregate an occurrence count but cannot apply a condition to filter the aggregated counts.
* The target system is not able to aggregate an occurrence count according to the given grouping criteria.
* It is only possible to generate a query up to an intermediate correlation rule of a chain.

The conversion backend should issue a warning to raise the user’s awareness about restrictions for aspects specified as "should". Examples are:

* Temporal relationships are recognized, but the order of the events cannot be recognized by the target system. This could cause false positives by differently ordered events.
* Temporal relationships are only recognized within static time boundaries, e.g. a timespan of 1h only matches if all events appear within a full hour, but not if some events appear in the previous and another event in the current hour. This could cause false negatives.

## Expression of Relationships In The Condition of Sigma Rules

This was the first approach defined in Sigma with aggregations and the near operator and is now obsolete. Sigma correlations are not based on this approach for the following reasons:

* The coupling of rules describing singular events and relationships between multiple events is inconsistent, as the rule writer must decide which rule contains the relationship definition in case of temporal relationships.
* It was inflexible because one Sigma rule refers exactly to one log source, which restricts the expression of relationships to events from the same log source.
* One of the goals of Sigma rules was to keep the condition logic simple. Especially the specification of temporal relationships can get quite complex in a query expression. Specifying correlation chains adds further complexity.
* The pipe syntax sometimes caused the rule contributors to consider it as a Splunk query or another target system-specific query language. Expressing these relationships in a “Sigmaish” way should not cause these associations.

## Type of rules
### Correlation rules

The purpose is to cover a detection like:

* X invalid login alerts on a unique host
* Invalid login alert on the same host but from X remote
* Alert A, B and C in the same timespan

### Global Filter rules

The purpose of Filter rules is to apply the same tuning on many rules with the goal to suppress matches of multiple rules. This is most commonly useful for environment specific tuning where a false positive prone application is used in an organization and its false positives are accepted.
Example: A valid GPO script that triggers multiple Sigma rules.


# Correlation rules

The rules in a multi-document YAML that build a correlation rule are not producing individual, independent queries. They are used as a tool to define more complex constructs out of basic Sigma detections. Therefore only the outermost correlation rule may define meta information such as status, level, date or anything else.
<!--  Discution from the former PR
secDre4mer Nov 27, 2023
Should be "generate".
Also: This implies that with this change, no current rules will generate queries (since they don't have that field).

phantinuss Nov 27, 2023 •
Nah you are right. It's affecting all existing rules.
But +1 on the rename

secDre4mer Nov 27, 2023

About rename: I find it a bit counter-intuitive that this field is called "generate". From a technical perspective it's correct (no queries are generated), but from a high-level user perspective, I don't know what's generated. That it defaults to true (according to documentation below) is also strange / unexpected.
Maybe we could invert it and call it silent instead? That would have the "expected" behaviour of defaulting to a zero value (that is, false) and it clarifies what this does (if it's set, the rule is silent and does not produce matches).

 Neo23x0 Dec 14, 2023

The default behaviour should be that the single rules in a correlation rule are silent.

Examples:

    The multiple failed logon followed by a successful logon example. You wouldn't want to trigger a rule and see a match for every failed logon.
    A rule that detects recon activity. You wouldn't want to see matches for every "net" command execution or every "ping".

So, the default behaviour of the field "silent", if we call it that way, should be "true" and the user can set it to "false" if he wants the single rules in the correlation to show up.

I wouldn't overcomplicate it with lists of selections.
But this opinion isn't by far as strong as the one I have on the default behaviour.
We can allow the user to provide a list of rule name that he wants to see matches for. (a list that disables the "silent" for 1-n of the sub rules)

phantinuss Dec 14, 2023 •

The issue that @secDre4mer raised was that how does that affect existing rules.

My proposal is to define it like this:

    We can switch back to silent is false by default (implicitly). And silent is true if you set it to true explicitly or if there is no level defined in a rule, which is the case for all "in-file/multi-document" correlation rules that are only used as aggregates.

 phantinuss Dec 14, 2023

Another idea how we could specify it:
If a rule has no level set, the default level is "informational". That also should work and we have no need to define either "generate" or "silent" at all.

-->

## File Structure
### YAML File

To keep the file names interoperable use the following:

- Length between 10 and 70 characters
- Lowercase
- No special characters only letters (a-z) and digits (0-9)
- Use `_` instead of a space
- Use `.yml` as a file extension

As a best practice use the prefix `mr_correlation_`.


### Schema

[meta-rule-schema](meta-rule-schema.json)

###  Syntax

A Sigma correlation is a dedicated YAML document.
Like sigma rules , correlation rules have a title and a unique id to identify them.

## Components

### Title

**Attribute:** title

A brief title for the rule that should contain what the rule is supposed to detect (max. 256 characters)
<!-- shouldn't it be mandatory ?-->

### Rule Identification

**Attribute:** id

Sigma meta-rules should be identified by a globally unique identifier in the *id* attribute.
For this purpose randomly generated UUIDs (version 4) are recommended but not mandatory.

An example for this is:

```yml
title: login brute force
id: 0e95725d-7320-415d-80f7-004da920fc11
```

### Related rules

**Attribute:** rules

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

### Correlation type

**Attribute:** type

Can be :
- event_count
- value_count
- temporal
- temporal_ordered

### Grouping

**Attribute:** group-by

optionally defines one or multiple fields which should be treated as separate event occurrence scope. Examples:
  * count events by user
  * temporal proximity must occur on one system by the same user


### Values Field Name selection

**Attribute:** field

Use by value_count correlation to define the field name use to count.

Example:
```yaml
field: User
group-by:
    - ComputerName
```

### Time Selection


**Attribute:** timespan

defines a time period in which the correlation should be applied.
The following format must be used: `number + letter (in lowercase)`
- Xs seconds
- Xm minutes
- Xh hours
- Xd days


<!-- TODO: Will we support a sum of the input values? Like 1h30m should be supported, shouldn't it? -->

### Condition Selection


**Attribute:** condition

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
condition
    gte: 100
```

**Subattribute:** field

Used by value_count correlation to define the field name which values are counted.

Example:
```yaml
condition
    field: user
    gte: 100
```

### Level

**Attribute:**  level

defines a severity level adjustment if the correlation matches.
This allows to give single event hits a low or informational severity and increasing this to higher levels in case of correlating appearances of events.

### Aliases

**Attribute:** aliases

defines field name aliases that are applied to correlated Sigma rules.
The defined aliases can then be defined in `group-by` and allows aggregation across different fields in different event types.

### Generate

**Attribute:** generate
<!-- TODO: Discuss: I think we agreed on switching the default behaviour back to 'true' -->
Usually if a Sigma rule is referenced by a correlation rule the query for the rule itself is not generated anymore.
This attribute overrides the behavior.
The idea is that two rules are created:

* one for the singular event with informational severity.
* the correlation rule that takes appearance of multiple events into account with a higher severity.

***************************************************
****************** NEED AN EXAMPLE ****************
***************************************************

## Metric Conditions

The field condition defines the condition that must evaluate to true to generate a match.
It operates on the count resulting from an event_count or value_count correlation.
It is a map of exactly one condition criterion:

* `gt`: The count must be greater than the given value
* `gte`: The count must be greater than or equal the given value
* `lt`: The count must be lesser than the given value
* `lte`: The count must be lesser than or equal the given value
* `range`: The count must be in the given range specified as value in the format `min..max`. The range includes the min and max values.

If you need more complex constructs, you can always chain correlation rules together. See the examples at the far bottom, for more details.

## Event Count (event_count)

Counts events occurring in the given time frame specified by the referred Sigma rule or rules.
The resulting query must count events for each group specified by group-by separately.
The condition finally defines how many events must occur to generate a search hit.

Need `group-by`, `timespan` and `condition`

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
## Value Count (value_count)

Counts values in a field defined by `field`.
The resulting query must count field values separately for each group specified by group-by.
The condition finally defines how many values must occur to generate a search hit.

Requires `group-by`,`timespan` and `condition` in correlation rule and `field` in correlation rule condition.

Simple example : Failed logon attempts with more than 100 different user accounts per source and destination at a day:

```yaml
title: Failed login
id: 0e95725d-7320-415d-80f7-004da920fc12
correlation:
  type: value_count
  rules:
      - 5638f7c0-ac70-491d-8465-2a65075e0d86
  field: User
  group-by:
      - ComputerName
      - WorkstationName
  timespan: 1d
  condition:
      gte: 100
```

## Temporal Proximity (temporal)


All events defined by the rules referred by the rule field must occur in the time frame defined by timespan.
The values of fields defined in group-by must all have the same value (e.g. the same host or user).

The time frame should not be restricted to boundaries if this is not required by the given backend.

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

## Ordered Temporal Proximity (temporal_ordered)

The *temporal_ordered* correlation type behaves like *temporal* and requires in addition that the events appear in the
order provided in the *rule* attribute.

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

## Field Name Aliases

Sometimes correlation of values in the same fields is not sufficient. E.g. a correlation rule might require to aggregate events that appear from a source address in one event and the same address as destination in another event. A Sigma correlation rule can contain an `aliases` attribute that defines an alias for different field names in events matched by different Sigma rules. The alias field names can then be referenced in `group-by` attributes and are resolved to their respective field names.

Aliases are defined as follows:

```
aliases:
  <alias name>:
    <Sigma rule name>: <source field name in event matched by Sigma rule>
[...]
```

The field names referenced in aliases must not necessarily appear in the Sigma rules, but in the events matched by the Sigma rules.

<!-- please verify that my understanding given in this section is correct -->
`<Sigma rule name>` is the name given by the `name` attribute. The `name` attribute is optional in general, but has to be defined, if you want to use `aliases`.

### Field Name Aliases Example

The following correlation rule defines field name aliases `internal_ip` and `remote_ip` that are used in the `group-by` attribute.
The `internal_ip` alias references the field `destination.ip` in the events matched by the Sigma rule `internal_error` and `source.ip` in the events matched by the Sigma rule `new_network_connection`.
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

<!-- TODO: This section needs some work after deciding to remove the action attribute -->
# Global Filter
## File Structure

### YAML File

To keep the file names interoperable use the following:

- Length between 10 and 70 characters
- Lowercase
- No special characters only letters (a-z) and digits (0-9)
- Use `_` instead of a space
- Use `.yml` as a file extension

As a best practice use the prefix `mr_filter_`

<!-- TODO: finalize the rx schema-->
### Schema

```yaml
title: //str
description: //str
action: //str
type: //str
logsource: # optional
    product: //str
    service: //str
global_filter:
    type: //rec
    required:
      detection: //rec
    optional:
      <selections> // rec
      rules: //arr # no defined rules means matching on all rules

```

### Syntax

Like Sigma rules, "Filter" rules have a `title` and an `id` to facilitate their management.
It has no other meta data like level or status because its purpose is to enrich an existing Sigma rule.


## Components

### title

**Attribute:** title

A brief title for the rule that should contain what the rule is supposed to detect (max. 256 characters)

### action

**Attribute:** action

must be `filter`

### Change to Condition

<!-- What would be an include filter? Something added as "or" to the referenced rules instead of "and not"? -->
**Attribute:** type

can be :
- include
- exclude

### Description

**Attribute:** description

A short description of the rule and the malicious activity that can be detected (max. 65,535 characters)

Relative rules

**Attribute:** rules

refers to one or multiple Sigma rules to be filter

### Log source

**Attribute**: logsource

See log source in [sigma specification](Sigma_specification.md)

### filter selection

**Attribute**: selection

See Detection in [sigma specification](Sigma_specification.md)

Example

```yaml
title: Filter Administrator account
description: The valid administrator account start with adm_
logsource:
    category: process_creation
    product: windows
global_filter:
  rules:
    - 6f3e2987-db24-4c78-a860-b4f4095a7095 # Data Compressed - rar.exe
    - df0841c0-9846-4e9f-ad8a-7df91571771b # Login on jump host
  selection:
      User|startswith: 'adm_'
  condition: selection
```

# Examples
This section gives complete examples in order to make it easier for people new to Sigma to get started and for showcasing new features of the Sigma standard. Use them as a blueprint for your own ideas.

## Correlation


### Failed Logins Followed by Successful Login

The following Correlation describes a use case in which an attacker successfully performs a brute-force attack. This example helps in showcasing some highlights:
 - You can use YAMLs multi document feature (`---`) to have everything grouped together in one file
 - Rules can be referenced in a human-friendly way using their unique `name`.
 - Correlations can be chained to express more complex use cases

```yml
title: Correlation - Multiple Failed Logins Followed by Successful Login
id: b180ead8-d58f-40b2-ae54-c8940995b9b6
status: experimental
description: Detects multiple failed logins by a single user followed by a successful login of that user
references:
    - https://reference.com
author: Florian Roth (Nextron Systems)
date: 2023/06/16
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
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
description: Detects a single failed login
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
