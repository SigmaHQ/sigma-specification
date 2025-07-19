# Sigma Filters Specification

The following document defines the standardized global filter that can be used with Sigma rules.

- Version 2.0.0
- Release date 2024-08-08

<!-- mdformat-toc start --slug=github --maxlevel=6 --minlevel=2 -->

- [Introduction](#introduction)
- [Global filter](#global-filter)
  - [File Structure](#file-structure)
    - [YAML File](#yaml-file)
    - [Schema](#schema)
    - [Syntax](#syntax)
  - [Components](#components)
    - [title](#title)
    - [Identification](#identification)
    - [Description](#description)
    - [Date](#date)
    - [Modified](#modified)
    - [Log source](#log-source)
    - [Global Filter](#global-filter)
      - [Relative rules](#relative-rules)
      - [filter selection](#filter-selection)
      - [filter condition](#filter-condition)
- [Examples](#examples)
- [History](#history)

<!-- mdformat-toc end -->

## Introduction<a name="introduction"></a>

The purpose of Filter rules is to apply the same tuning on many rules with the goal to suppress matches of multiple rules. This is most commonly useful for environment specific tuning where a false positive prone application is used in an organization and its false positives are accepted.

Example: A valid GPO script that triggers multiple Sigma rules.

## Global filter<a name="global-filter"></a>

### File Structure<a name="file-structure"></a>

#### YAML File<a name="yaml-file"></a>

To keep the file names interoperable use the following:

- Length between 10 and 70 characters
- Lowercase
- No special characters only letters (a-z) and digits (0-9)
- Use `_` instead of a space
- Use `.yml` as a file extension

As a best practice use the prefix `mf_`

#### Schema<a name="schema"></a>

[Sigma Filters JSON Schema](/json-schema/sigma-filters-schema.json)

#### Syntax<a name="syntax"></a>

A Sigma global filter is a dedicated YAML document.
Like Sigma rules, "Filter" rules have a `title` and a unique `id` to identify them.
It has no `level` or `status` because its purpose is to enrich an existing Sigma rule.

### Components<a name="components"></a>

#### title<a name="title"></a>

**Attribute:** title

**Use:** mandatory

A brief title for the rule that should contain what the rule is supposed to detect (max. 256 characters)

#### Identification<a name="identification"></a>

**Attribute:** id

**Use:** optional

Sigma meta-rules should be identified by a globally unique identifier in the *id* attribute.
For this purpose randomly generated UUIDs (version 4) are recommended but not mandatory.

An example for this is:

```yml
title: login brute force
id: 0e95725d-7320-415d-80f7-004da920fc11
```

#### Description<a name="description"></a>

**Attribute:** description

**Use:** optional

A short description of the rule and the malicious activity that can be detected (max. 65,535 characters)

#### Date<a name="date"></a>

**Attribute**: date

**Use:** optional

Creation date of the meta filter. \
Use the ISO 8601 date with separator format : YYYY-MM-DD

#### Modified<a name="modified"></a>

**Attribute**: modified

**Use:** optional

*Last* modification date of the meta filter. \
Use the ISO 8601 date with separator format : YYYY-MM-DD

#### Log source<a name="log-source"></a>

**Attribute**: logsource

**Use:** mandatory

Read more on the `logsource` attribute in the [Sigma Rules Specification](/specification/sigma-rules-specification.md)

#### Global Filter<a name="global-filter"></a>

**Attribute**: filter

**Use:** mandatory

##### Relative rules<a name="relative-rules"></a>

**Attribute:** rules

**Use:** mandatory

refers to one or multiple Sigma rules where to add the filter

##### filter selection<a name="filter-selection"></a>

**Attribute**: selection

**Use:** mandatory

Read more on the 'detection' section in the [Sigma Rules Specification](/specification/sigma-rules-specification.md)

##### filter condition<a name="filter-condition"></a>

**Attribute**: condition

**Use:** mandatory

Read more on the 'detection' field in the [Sigma Rules Specification](/specification/sigma-rules-specification.md)

## Examples<a name="examples"></a>

This section gives complete examples in order to make it easier for people new to Sigma to get started and for showcasing new features of the Sigma standard. Use them as a blueprint for your own ideas.

```yaml
title: Filter Administrator account
description: The valid administrator account start with adm_
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 6f3e2987-db24-4c78-a860-b4f4095a7095 # Data Compressed - rar.exe
        - df0841c0-9846-4e9f-ad8a-7df91571771b # Login on jump host
    selection:
        User|startswith: 'adm_'
    condition: selection
```

## History<a name="history"></a>

- 2024-08-08 Specification v2.0.0
