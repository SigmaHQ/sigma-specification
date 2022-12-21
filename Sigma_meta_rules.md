# Sigma Meta Rules <!-- omit in toc -->

- [Introduction](#introduction)
- [Correlation](#correlation)
  - [YAML File](#yaml-file)
  - [Structure](#structure)
    - [Schema](#schema)
    - [Syntax](#syntax)
    - [Components](#components)
      - [action](#action)
      - [name](#name)
      - [Relative rules](#relative-rules)
      - [Correlation type](#correlation-type)
      - [Regrouping](#regrouping)
      - [time Selection](#time-selection)
      - [condition](#condition)
      - [level](#level)
      - [aliases](#aliases)
    - [Correlation Types](#correlation-types)
      - [Event Count (event\_count)](#event-count-event_count)
      - [Value Count (value\_count)](#value-count-value_count)
      - [Temporal Proximity (temporal)](#temporal-proximity-temporal)
    - [Conditions](#conditions)
    - [Field Name Aliases](#field-name-aliases)
      - [Field Name Aliases Example](#field-name-aliases-example)
    - [Chaining](#chaining)
      - [Correlation Chaining Example](#correlation-chaining-example)
    - [File Inclusion](#file-inclusion)
  - [Compatibility](#compatibility)
  - [Alternative Proposals](#alternative-proposals)
    - [Expression of Relationships Inside Condition of Sigma Rules](#expression-of-relationships-inside-condition-of-sigma-rules)
- [Global filter or Defeats](#global-filter-or-defeats)
  - [YAML File](#yaml-file-1)
  - [Structure](#structure-1)
    - [Schema](#schema-1)
    - [Components](#components-1)
      - [action](#action-1)
      - [name](#name-1)
      - [Decription](#decription)
      - [Relative rules](#relative-rules-1)
      - [Log source](#log-source)
      - [filter selection](#filter-selection)

# Introduction

A meta-rule is a rule over sigma rules.  
With them you can do :
- Correlation
- Global filter or Defeats 

# Correlation

All rules in a file, basic event rules as well as correlations, might contain an additional attribute generate.  
If this is set to true, the rule will generate a query, even if it is referred by other correlations, which would normally cause that the rule wouldn’t generate a separate query."

## YAML File

To keep the file names interoperable use the following:

- Length between 10 and 70 characters
- Lowercase
- No special characters only letters (a-z) and digits (0-9)
- Use `_` instead of a space
- Use `.yml` as a file extension

use prefix `mr_correlation_` and (`mr_filter_`)  ? 

## Structure
### Schema

```yaml
action: //str
name: //str  <- title ?
type: //str
rules: //map
group-by: //map
timespan: //str
condition: //map
level: //str
aliases: //map
ordered: //boolean
```

### Syntax

A Sigma correlation is a dedicated YAML document located in the same file as the related Sigma rules. Each Sigma rule referred by a correlation contains a field name at the top level that is used as reference identifier. Example:

```
title: Failed Login Attempt
name: failed_login
[...]
```

### Components

#### action

**Attribute:** action

must be `correlation`

#### name

**Attribute:** name

Name use as title for the alert

#### Relative rules

**Attribute:** rules

refers to one or multiple Sigma rules or correlations (allowing definition of chains of correlations) defining events to be correlated
** MUST be by the ID as title can change**

#### Correlation type

**Attribute:** type

is the correlation type (see below)

#### Regrouping

**Attribute:** group-by

optionally defines one or multiple fields which should be treated as separate event occurrence scope. Examples:
  * count events by user
  * temporal proximity must occur on one system by the same user

#### time Selection

**Attribute:** timespan

defines a time period in which the correlation should be applied

#### condition

**Attribute:** condition

defines a condition for correlations counting entities (see below)

#### level

**Attribute:**  level

defines a severity level adjustment if the correlation matches.  
This allows to give single event hits a low or informational severity and increasing this to higher levels in case of correlating appearances of events.

#### aliases

**Attribute:** aliases

defines field name aliases that are applied to correlated Sigma rules.  
The defined aliases can then be defined in `group-by` and allows aggregation across different fields in different event types.

### Correlation Types

The following correlation types are defined.  
They are referred in the type field of a correlation document.  
Further correlation rule types might be added in the future.

#### Event Count (event_count)

Counts events occurring in the given time frame specified by the referred Sigma rule or rules.  
The resulting query must count events for each group specified by group-by separately.  
The condition finally defines how many events must occur to generate a search hit.


Simple example : More than or equal 100 failed login attempts to a destination host in an hour:

```yaml
action: correlation
name: many_failed_logins
type: event_count
rules: failed_login
group-by:
    - ComputerName
timespan: 1h
condition:
    gte: 100
```

#### Value Count (value_count)

Counts values in a field defined by field.  
The resulting query must count field values separately for each group specified by group-by.  
The condition finally defines how many values must occur to generate a search hit.

Simple example : Failed logon attempts with more than 100 different user accounts per source and destination at a day:

```yaml
action: correlation
type: value_count
rules: failed_login
field: User
group-by:
    - ComputerName
    - WorkstationName
timespan: 1d
condition:
    gte: 100
```

#### Temporal Proximity (temporal)

All events defined by the rules referred by the rule field must occur in the time frame defined by timespan.  
The values of fields defined in group-by must all have the same value (e.g. the same host or user).  
If the bool value ordered is set to true, the events should occur in the given order.  
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

### Conditions

The field condition defines the condition that must evaluate to true to generate a hit. It operates on the count resulting from an event_count or value_count correlation. It is a map of exactly one condition criteria:

* gt: the count must be greater than the given value
* gte: the count must be greater than or equal the given value
* lt: the count must be lesser than the given value
* lte: the count must be lesser than or equal the given value
* range: the count must be in the given range specified as value in the format min..max. The ranges include the min and max values.

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

####  Field Name Aliases Example

The following correlation rule defines field name aliases `internal_ip` and `remote_ip` that are used in the `group-by` attribute. The `internal_ip` alias references to the field `destination.ip` in the events matched by the Sigma rule `internal_error` and `source.ip` in the events matched by the Sigma rule `new_network_connection`. The correlation rule then only matches if the events appear with the same address in the respective fields of the events matching the referenced Sigma rules.

```yaml
name: internal_error
detection:
  selection:
    http.response.status_code: 500
  condition: selection
---
name: new_network_connection
detection:
  selection:
    event.category: network
    event.type: connection
    event.outcome: success
  condition: selection
---
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

### Chaining

If correlation rules are chained, the final rules of the chain must be used to generate the query. Sigma rules referred by correlations and intermediate correlation rules are normally not used to generate a query. This default behavior can be overridden by setting the generate attribute to true.

#### Correlation Chaining Example

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

The grouping by the ComputerName field is assumed for the many_failed_logins correlation rule but not for the final correlation.

### File Inclusion

Sometimes it makes sense to define rules for events in a different file than the correlations, e.g. to make them reusable from multiple correlations or make it possible to use them independently. For this reason, another document type is included for file inclusion. An inclusion can be defined by setting the action attribute to include. Only the attribute filename is currently supported. It references the Sigma rule file that should be included. Example:

```
action: include
filename: other_sigma_rule.yml
```

All rules contained in the referenced file are handled as if they were defined in the including file. The file path is relative to the including file. For security reasons it is not allowed to traverse the path upwards.

## Compatibility

Sigma correlations might exceed the capabilities of target systems for which queries are generated or required features are only supported partially by the target. Target-specific restrictions should be handled in a way that ensures that the generated queries do not create or raise users awareness for results that:

* could be misinterpreted
* cause a huge amount of false positives compared to the query intended by the rule
* cause false negatives

An error must be raised by the conversion backend if it should generate a query from a rule which contains a feature that is not supported but specified as must. Examples are:

* The target system can aggregate an occurrence count but cannot apply a condition to filter the aggregated counts.
* The target system is not able to aggregate an occurrence count according to the given grouping criteria.
* It is only possible to generate a query up to an intermediate correlation rule of a chain.

The conversion backend should issue a warning to raise the user’s awareness about restrictions for aspects specified as should. Examples are:

* Temporal relationships are recognized, but the order of the events cannot be recognized by the target system. This could cause false positives by differently ordered events.
* Temporal relationships are only recognized within static time boundaries, e.g. a timespan 1h only matches if all events appear within a full hour, but not if some events appear in the previous and another event in the current hour. This could cause false negatives.


## Alternative Proposals
### Expression of Relationships Inside Condition of Sigma Rules

This was the first approach defined in Sigma with aggregations and the near operator. Sigma correlations are not based on this approach for the following reasons:

* The coupling of rules describing singular events and relationships between multiple events is inconsistent, as the rule writer must decide which rule contains the relationship definition in case of temporal relationships.
* It was inflexible because one Sigma rule refers exactly to one log source, which restricts the expression of relationships to events from the same log source.
* One of the goals of Sigma rules was to keep condition logic simple. Especially the specification of temporal relationships can get quite complex in a query expression. Specifying correlation chains adds further complexity.
* The pipe syntax sometimes caused that rule contributors considered it as Splunk query or another target system-specific query language. Expressing these relationships in a “Sigmaish” way should not cause these associations.

# Global filter or Defeats

## YAML File

To keep the file names interoperable use the following:

- Length between 10 and 70 characters
- Lowercase
- No special characters only letters (a-z) and digits (0-9)
- Use `_` instead of a space
- Use `.yml` as a file extension

use prefix `mr_correlation_` and (`mr_filter_`)  ? 

## Structure
### Schema

```yaml
action: //str
name: //str  <- title ?
description: //str
rules: //map
logsource:
    product: //str
    service: //str
selection:
    type: //rec
```

### Components

#### action

**Attribute:** action

must be `filter` ?

#### name

**Attribute:** name

Name use as title for the alert

#### Decription

**Attribute:** description

A short description of the rule and the malicious activity that can be detected (max. 65,535 characters)

#### Relative rules

**Attribute:** rules

refers to one or multiple Sigma rules to be filter

#### Log source

**Attribute**: logsource

See log source in [sigma specification](Sigma_specification.md)

#### filter selection

**Attribute**: selection

See Detection in [sigma specification](Sigma_specification.md)
