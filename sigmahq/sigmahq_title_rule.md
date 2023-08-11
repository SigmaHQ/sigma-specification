# SigmaHQ Rule Conventions <!-- omit in toc -->

This document provide general guidelines and tips on how to write a title for a sigma rule.

Note that this is by no means an exhaustive list, it is meant to be more of a general guide for inspiration and to reduce exchange during PRs


## Summary

- [Summary](#summary)
- [Generality](#generality)
- [Structure](#structure)
  - [Prefix](#prefix)
  - [Suffix](#suffix)
  - [Description](#description)


## Generality

Bearing in mind that the title is one of the first things that an analyst will see. It should therefore be used as a clue and be clear as possible to guide the consideration of the alert.

The title and level of the rule must be consistent



## Structure

Titles can be split with "-" : `Prefix - Description - Sufix`


### Prefix (Optional)

It is used to give a category or type of malware, an APT 

Examples:

- HackTool
- PUA
- Remote Access Tool


Specific wording example:
- "ATP27 - "
- "ATP29 - "
- "UNC2452 - "
- "UNC4841 - "

### Suffix (Optional)

Sometimes the detection are duplicated across different log-source with little changes to their logic. This is common in the case of Process Creation rules targeting the PowerShell process and rules using ScriptBlockText to check for the same. A suffix in this case will be used to offer such distinction.


Example:


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
- "Potential "



`high` rules requires a prompt review
Wording :
- "Suspicious "



`critical` rules should be reviewed immediately
The title must therefore be precise.