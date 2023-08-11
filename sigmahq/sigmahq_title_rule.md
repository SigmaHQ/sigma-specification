# SigmaHQ Rule Conventions <!-- omit in toc -->

This document describes how to write a title for a sigma rule.
It is impossible to be exhaustive, so it is more of a guide than a standard.

## Summary

- [Summary](#summary)
- [Generality](#generality)
- [Structure](#structure)
  - [Prefix](#prefix)
  - [Suffix](#suffix)
  - [Description](#description)


## Generality

Bear in mind that the title is the first thing the operator will see.
It should therefore be used as a clue to guide the consideration of the alert.

The title and level of the rule must be consistent


## Structure

Title can be split with "-" : `Prefix - Description - Sufix`

### Prefix
It is Optional.
It is used to give a category or type of malware, an APT 

Commun wordding:
- Hack Tool
- Lolbin (lolbas)
- PUA
- Remote Access Tool

Specific wording example:
- "ATP27 - "
- "ATP29 - "
- "UNC2452 - "
- "UNC4841 - "

### Suffix
It is Optional.
It is used to differentiate the same detection but on a different logsource.

Exemple:
```yaml
title: Invoke-Obfuscation Obfuscated IEX Invocation
title: Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell
title: Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module
title: Invoke-Obfuscation Obfuscated IEX Invocation - Security
title: Invoke-Obfuscation Obfuscated IEX Invocation - System
```

### Description

The point here is to explain the alert in a meaningful way.
The title does not need to use the terms "Detect", "Detection" or "Detection".

We use a simple formula to describe the alert.
Example:
- "7Zip Compressing ..."
- "Add User to ..."
- "Bypass UAC Using ..."
- "Renamed xxx Execution"
- "UAC Bypass Using ..."


`informational` and `low` are not intended for everyday use and are subject to many false positives.
The title should therefore be general.

Example : `Net.exe Execution` 

`medium` rules can have false positives and requires further analysis
Wording :
- "Suspicious "


`high` rules requires a prompt review
Wording :
- "Potential "


`critical` rules should be reviewed immediately
The title must therefore be precise.