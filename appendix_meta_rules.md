# Sigma Correlation <!-- omit in toc -->

The following document defines the standardized correlation that can be used in Sigma rules.

* Version 2.0.0
* Release date 2023/07/01

- [Introduction](#introduction)
  - [Compatibility](#compatibility)
  - [Expression of Relationships In The Condition of Sigma Rules](#expression-of-relationships-in-the-condition-of-sigma-rules)
  - [Type of rules](#type-of-rules)
    - [Correlation rules](#correlation-rules)
    - [File Inclusion](#file-inclusion)
    - [Filter rules](#filter-rules)
- [Correlation rules](#correlation-rules-1)
  - [File Structure](#file-structure)
    - [YAML File](#yaml-file)
    - [Schema](#schema)
    - [Syntax](#syntax)
  - [Components](#components)
    - [Title](#title)
    - [Rule Identification](#rule-identification)
    - [Action](#action)
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
  - [Field Name Aliases](#field-name-aliases)
    - [Field Name Aliases Example](#field-name-aliases-example)
- [File Inclusion](#file-inclusion-1)
  - [File structure](#file-structure-1)
    - [YAML File](#yaml-file-1)
    - [Schema](#schema-1)
    - [Syntax](#syntax-1)
  - [Components](#components-1)
    - [Action:](#action-1)
    - [Filename:](#filename)
- [Filter](#filter)
  - [File Structure](#file-structure-2)
    - [YAML File](#yaml-file-2)
    - [Schema](#schema-2)
    - [Syntax](#syntax-2)
  - [Components](#components-2)
    - [title](#title-1)
    - [action](#action-2)
    - [Change to Condition](#change-to-condition)
    - [Description](#description)
    - [Log source](#log-source)
    - [filter selection](#filter-selection)

# Introduction

Sometimes you need more advanced searches than simple selections.
For that you can use meta-rules that correlate multiple Sigma rules.

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

* X invalid login alerts on an unique host
* Invalid login alert on the same host but from X remote
* Alert A, B and C in the same timespan

### File Inclusion

Sometimes it makes sense to define rules for events in a different file than the correlations, e.g. to make them reusable from multiple correlations or make it possible to use them independently.  
For this reason, another document type is included for file inclusion.  
An inclusion can be defined by setting the action attribute to include.  
All rules contained in the referenced file are handled as if they were defined in the including file.

###  Filter rules

The purpose of Filter rules is to cover the same tuning for many rules. They are used to suppress matches of multiple rules. This is most commonly useful for environment specific tuning where a false positive prone application is used in an organization and it's false positives are accepted.
Example: A valid GPO script that triggers X Sigma rules.


# Correlation rules

All rules in a file, basic event rules as well as correlations, might contain an additional attribute called "generated".  
If it is set to true, the rule will generate a query, even if it is referred to by other correlations. Otherwise by default no "standalone" query would be generated for this rule.

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

****************************
****** NEED SOME WORK ******
****************************

```yaml
type: //rec

required:
  title: //str
  action: //str
  type: //str

optional:
  id: //str
  rules: //map
  field: //str
  group-by: //map
  timespan: //str
  condition: //map
    gt: //int
    gte: //int
    lt: //int
    lte: //int
    range: //int .. //int
  level: //str
  aliases: //map
  ordered: //boolean
  generate: //boolean
```


###  Syntax

A Sigma correlation is a dedicated YAML document.  
Like sigma rules , correlation rules have a title and a unique id to identify them.

## Components

### Title 

**Attribute:** title

A brief title for the rule that should contain what the rule is supposed to detect (max. 256 characters)

### Rule Identification

**Attribute:** id

Sigma meta-rules should be identified by a globally unique identifier in the *id* attribute.  
For this purpose randomly generated UUIDs (version 4) are recommended but not mandatory. 

An example for this is:

```yml
title: login brute force
id: 0e95725d-7320-415d-80f7-004da920fc11
```

### Action

**Attribute:** action

This field is mandatory and must have the value `correlation`

```yml
title: login brute force
id: 0e95725d-7320-415d-80f7-004da920fc11
action: correlation
```

### Related rules

**Attribute:** rules

Refers to one or multiple Sigma or Correlations rules.
Allowing the user to chain multiple correlations together.
A rule can be referred to by the `id` of a sigma rule.

Latter is a human-readable name and improves the readability of correlation rules.
In this case, the tool must be able to manage the human-to-id correspondence automatically.

```yaml
title: login brute force
id: 0e95725d-7320-415d-80f7-004da920fc11
action: correlation
rules:
    - 5638f7c0-ac70-491d-8465-2a65075e0d86 # ID of the low firewall rule for action: block
    - firewall_block  # the internal tools have a lookup table to the correct rule id
```

### Correlation type

**Attribute:** type

Can be :
- event_count
- value_count
- temporal


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

### Condition Selection

**Attribute:** condition

defines a condition for correlations counting entities see [Metric Conditions](#metric-conditions)

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


## Event Count (event_count)

Counts events occurring in the given time frame specified by the referred Sigma rule or rules.  
The resulting query must count events for each group specified by group-by separately.  
The condition finally defines how many events must occur to generate a search hit.

Need `group-by`, `timespan` and `condition`

Simple example : More than or equal 100 failed login attempts to a destination host in an hour:

```yaml
title: Many failed logins
id: 0e95725d-7320-415d-80f7-004da920fc11
action: correlation
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

Need `field`, `group-by`,`timespan` and `condition`

Simple example : Failed logon attempts with more than 100 different user accounts per source and destination at a day:

```yaml
title: Failed login
id: 0e95725d-7320-415d-80f7-004da920fc12
action: correlation
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
If the bool value `ordered` is set to true, the events should occur in the given order.  
The time frame should not be restricted to boundaries if this is not required by the given backend.

Simple example : Reconnaissance commands defined in three Sigma rules are invoked in arbitrary order within 5 minutes on a system by the same user:

```yaml
action: correlation
type: temporal
rules:
    - recon_cmd_a
    - recon_cmd_b
    - recon_cmd_c
group-by:
    - ComputerName
    - User
timespan: 5m
ordered: false
```

When `ordered` is set to true the correlation rules are chained, the final rules of the chain must be used to generate the query.
Sigma rules referred by correlations and intermediate correlation rules are by default not used to generate a query.
This default behavior can be overridden by setting the `generate` attribute to true.

Many failed logins as defined above are followed by a successful login by of the same user account within 1 hour:

```yaml
action: correlation
type: temporal
rule:
    - many_failed_logins
    - successful_login
group-by:
    - User
timespan: 1h
ordered: true
```

Nota:
Even if the rule many_failed_logins use a grouping by the "ComputerName" field,the correlation rule only use it own `group-by` "User".

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
action: correlation
type: temporal
rule:
  - internal_error
  - new_network_connection
group-by:
  - internal_ip
  - remote_ip
timespan: 10s
ordered: true
aliases:
  internal_ip:
    internal_error: destination.ip
    new_network_connection: source.ip
  remote_ip:
    internal_error: source.ip
    new_network_connection: destination.ip
```

# File Inclusion

## File structure
### YAML File

To keep the file names interoperable use the following:

- Length between 10 and 70 characters
- Lowercase
- No special characters only letters (a-z) and digits (0-9)
- Use `_` instead of a space
- Use `.yml` as a file extension

For the best pratice use the prefix `mr_include_`

### Schema
```yaml
action: //str
filename: //map
```
### Syntax
Only the attribute filename is currently supported.  
It references the Sigma rule file that should be included.

## Components
### Action:

**Attribute:** action

must be `include`

### Filename:

**Attribute:** filename

A list of the sigma rules.

The file path is relative to the including file.

For security reasons it is not allowed to traverse the path upward.

Example:

```yaml
action: include
filename: other_sigma_rule.yml
```

# Filter
## File Structure	

### YAML File

To keep the file names interoperable use the following:

- Length between 10 and 70 characters
- Lowercase
- No special characters only letters (a-z) and digits (0-9)
- Use `_` instead of a space
- Use `.yml` as a file extension

As a best practice use the prefix `mr_filter_`

### Schema

```yaml
title: //str
description: //str
action: //str
type: //str
rules: //map
logsource:
    product: //str
    service: //str
selection:
    type: //rec
```

### Syntax

Like Sigma rules, "Filter" rules have a title.  
They don't have an id or level as they use the one from the referenced rules.

## Components

### title 

**Attribute:** title

A brief title for the rule that should contain what the rule is supposed to detect (max. 256 characters)

### action

**Attribute:** action

must be `filter`

### Change to Condition 

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
action: filter
type: exclude
rules: 
    - 6f3e2987-db24-4c78-a860-b4f4095a7095 # Data Compressed - rar.exe
    - df0841c0-9846-4e9f-ad8a-7df91571771b # Login on jump host
logsource:
    category: process_creation
    product: windows 
selection:
    User|startswith: 'adm_'
```
