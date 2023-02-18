# SigmaHQ Custom Specification <!-- omit in toc -->

This document describe an addtional set of custom requirements enfroced by the SigmaHQ rule repository in order to ensure an easy to maintain rule base. For the general Sigma specficiation please read the [Sigma_specification.md](../Sigma_specification.md).

## Summary

- [Summary](#summary)
- [Structure](#structure)
- [Filenames](#filenames)
- [Titles](#titles)
- [Status](#status)
- [References](#references)
- [Single Item Lists](#single-item-lists)

## Structure

The rules consist of a few required sections and several optional ones.

```yaml
title [required]
id [required]
related [optional]
   - id {rule-id}
      type {type-identifier}
status [required]
description [required]
references [required]
author [required]
date [required]
modified [optional]
tags [required]
logsource [required]
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
falsepositives [required]
level [required]
```

## Filenames

All rule filename must follow the convention described in [Sigmahq_filename_rule.md](./Sigmahq_filename_rule.md)

## Titles

All SigmaHQ rules must titles must use title casing

Example:

```yml
title: Suspicious Office Child Process
```

## Status

All newly created rules must start with a status of `experimental`

## References

All rules must provide a public reference when possible

## Single Item Lists

Single item list must be expressed in the same line instead of multi-line.

Example of single list items:

```yml
detection:
    selection:
        Image|endswith: '\example.exe'
```

Example of multi item list:

```yml
detection:
    selection:
        Image|endswith:
            - '\example_1.exe'
            - '\example_2.exe'
            - '\example_3.exe'
```
