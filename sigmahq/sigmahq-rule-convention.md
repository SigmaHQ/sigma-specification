# SigmaHQ Rule Conventions

This document describes an additional set of rule conventions enforced by the SigmaHQ rule repository in order to ensure an easy to maintain rule base.

For the general Sigma rule specification please read see [this](/specification/sigma_rules.md)

<!-- mdformat-toc start --slug=github --maxlevel=6 --minlevel=2 -->

- [Structure](#structure)
- [Filenames](#filenames)
- [Indentation](#indentation)
- [Titles](#titles)
- [Status](#status)
- [Description](#description)
- [References](#references)
- [Detection](#detection)
  - [Item Lists](#item-lists)
  - [Condition](#condition)
- [False Positives](#false-positives)

<!-- mdformat-toc end -->

## Structure<a name="structure"></a>

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

## Filenames<a name="filenames"></a>

All rule filename must follow the convention described in the [SigmaHQ Filename Convention](./sigmahq_filename_convention.md) file.

## Indentation<a name="indentation"></a>

The recommended indentation is `4` spaces.

## Titles<a name="titles"></a>

All SigmaHQ rule titles must use title casing

Example:

```yml
title: Suspicious Office Child Process
```

## Status<a name="status"></a>

All newly created rules must start with a status of `experimental`

## Description<a name="description"></a>

- All rule descriptions must explain what the rule detects. A best practice therefore is to start with the word `Detects`
- If a description text is too long or it's expressing multiple ideas. It's advised to use the pipe symbol `|` to signify a multiline string. Example:

```yml
description: |
    Detects password dumper activity by monitoring remote thread creation EventID 8 in combination with the lsass.exe process as TargetImage.
    The process in field Process is the malicious program. A single execution can lead to hundreds of events.
```

## References<a name="references"></a>

- All rules must provide a public reference, if possible.
- References to the MITRE ATT&CK website are not allowed. Instead they should be expressed as tags using the appropriate MITRE tags.
- References to git-based platforms such as Github or Gitlab must be provided as permalinks instead of main or master branch links. This is to avoid any future confusion in the intended reference in case the maintainers of said branches introduce new changes.

## Detection<a name="detection"></a>

### Item Lists<a name="item-lists"></a>

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

### Condition<a name="condition"></a>

- When possible, it is recommended to use conditions in the form `1 of selection_*` or `1 of selection_*` in order to make them more readable.
- When filtering values in the condition, it's recommended to name the filters in one of two ways:
  - `filter_main_*`: For filters that are mandatory to the rule's logic, or if the excluded behavior or software is present by default or very common.
  - `filter_optional_*`: For filters that are based on behaviors or software that aren't part of the default installation of the OS or service being targeted.

## False Positives<a name="false-positives"></a>

- If the rule author expects false positives (found during testing or via external references), then it must be expressed as clear as possible. For example:

```yml
falsepositives:
    - During software X installation the process Y is known to behave similarly as Z 
    - Administrators or administrator scripts might sometimes generate similar activity
```

- In cases where the author doesn't know of any false positives then value the should be `Unknown`.
- If the rule author doesn't expect false positives the value should be `Unlikely`.

Also please note the following

- Keywords such as `None`, `Pentest`, `Penetration Test`, `Red Team`, Etc, are not accepted as valid values.
