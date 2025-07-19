# SigmaHQ Title Conventions

This document provides general guidelines and tips on how to write titles for sigma rules.

Note that this is by no means an exhaustive list. It is meant to be a general guide for inspiration and to have an easily sharable resource for new contributors (e.g. a resource to link at in PR discussions).

<!-- mdformat-toc start --slug=github --maxlevel=6 --minlevel=2 -->

- [Summary](#summary)
- [Structure](#structure)
  - [Prefix (Optional)](#prefix-optional)
  - [Suffix (Optional)](#suffix-optional)
  - [Main Title](#main-title)
    - [Informational / Low Level Rules](#informational--low-level-rules)
    - [Medium Level Rules](#medium-level-rules)
    - [High Level Rules](#high-level-rules)
    - [Critical Level Rules](#critical-level-rules)

<!-- mdformat-toc end -->

## Summary<a name="summary"></a>

Bearing in mind that the title is one of the first things that an analyst will see. It should therefore be used as a clue and be as clear as possible to guide the assessment of the alert.

The title and level of the rule must be consistent

## Structure<a name="structure"></a>

Titles can be split with "-" : `Prefix - Main Title - Suffix`

### Prefix (Optional)<a name="prefix-optional"></a>

It is used to give a category, type of malware or name a threat actor. The choice depends highly on the type of rule.

Examples:

- HackTool
- PUA
- Remote Access Tool

Specific wording example:

- "ATP27 - "
- "ATP29 - "
- "UNC2452 - "
- "UNC4841 - "

### Suffix (Optional)<a name="suffix-optional"></a>

Sometimes the detections are duplicated across different `logsource`s with little changes to their logic. This is common in the case of Process Creation rules targeting the PowerShell process. Those rules are typically duplicated for the different PowerShell `logsource`s using ScriptBlockText to check for the same characteristics. A suffix in this case will be used to differentiate between the rules of the different `logsource`s.

Example:

```yaml
title: Invoke-Obfuscation Obfuscated IEX Invocation
title: Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell
title: Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module
title: Invoke-Obfuscation Obfuscated IEX Invocation - Security
title: Invoke-Obfuscation Obfuscated IEX Invocation - System
```

### Main Title<a name="main-title"></a>

The point of a description is to explain the alert in a meaningful way.

The title does not need to use the terms "Detect" or "Detection". It doesn't have to be a sentence. A keyword style increases the information density.

We use a simple formula to describe the alert.
Example:

- "7Zip Compressing ..."
- "Add User to ..."
- "Bypass UAC Using ..."
- "Renamed xxx Execution"
- "UAC Bypass Using ..."

#### Informational / Low Level Rules<a name="informational--low-level-rules"></a>

Events matching rules of level `informational` or `low` are not intended to be used to create alerts on their own. Their purpose is to conserve events or criteria of relevance, to be used in correlations or for ideas for threat hunting. A rule of those levels will by definition not create false positives as they should not be used for alerting.

The title should therefore be general and should not indicate that the rule describes suspicious or malicious behavior.

Example : `Net.exe Execution`

#### Medium Level Rules<a name="medium-level-rules"></a>

Events matching `medium` level rules rules can have environment dependent false positives and require a tuning/evaluation phase before deploying to production environments.

Keywords used to indicate this:

- "Potential "

#### High Level Rules<a name="high-level-rules"></a>

Events matching `high` level rules requires a prompt review.

Keywords used to indicate this:

- "Suspicious "

#### Critical Level Rules<a name="critical-level-rules"></a>

Events matching `critical` level rules should be reviewed immediately
The title must therefore be precise and indicate the specific threat.

Keywords used to indicate this:

- "Malware"
- "Exploit"
- "... Attempt"
- "<Threat Actor> Activity"
