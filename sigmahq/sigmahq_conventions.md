# SigmaHQ Rule Conventions <!-- omit in toc -->

This document describes an additional set of rule conventions enforced by the SigmaHQ rule repository in order to ensure an easy to maintain rule base. 
For the general Sigma specification please read the [Sigma_specification.md](../Sigma_specification.md).

## Summary

- [Summary](#summary)
- [Structure](#structure)
- [Filenames](#filenames)
- [Indentation](#indentation)
- [Titles](#titles)
- [Status](#status)
- [Description](#description)
- [References](#references)
- [Detection](#detection)
  - [Item Lists](#item-lists)
- [False Positives](#false-positives)

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

## Indentation

The recommended indentation is `4` spaces.

## Titles

All SigmaHQ rule titles must use title casing

Example:

```yml
title: Suspicious Office Child Process
```

## Status

All newly created rules must start with a status of `experimental`

## Description

- All rule descriptions must explain what the rule detects. A best practice therefore is to start with the word `Detects`
- If a description text is too long or it's expressing multiple ideas. It's advised to use the pipe symbole `|` to signify a multiline string. Example:

```yml
description: |
    Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage.
    The process in field Process is the malicious program. A single execution can lead to hundreds of events.
``` 

## References

- All rules must provide a public reference, if possible.
- References to the MITRE ATT&CK website are not allowed. Instead they shloud be expressed as tags using the appropriate MITRE tags.
- References to git-based platforms such as Github or Gitlab must be provided as permalinks instead of main or master branch links. This is to avoid any future confusion in the intended reference in case the maintainers of said branches introduce new changes.

## Detection

### Item Lists

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

## False Postives

- If the rule author expects false positives (found during testing or via external references), then it must be expressed as clear as possible. For example:

```yml
falsepositives:
    - During software X installation the process Y is known to behave similarly as Z 
    - Administrators or administrator scripts might sometimes generate similar activity
```

- In cases where the author doesn't know of any false positives then value the should be `Unknown`.
- If the rule author doesn't expect false positives the value should be `Unlikely`.

Also please note the following

- Keywords such as `None`, `Pentest`, `Penetration Test`, `Red Team` are not accepted as valid values.
