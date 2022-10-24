# SigmaHQ Validation test Normalisation <!-- omit in toc -->

This page defines some standardized tests that are used to validate Sigma rules.  
These tests don't enforce the Sigma specification but enforce rule conventions to help organize a big rule repository such as the SigmaHQ rule repo.

Reference: Sigma specification 1.0.1

# Summary

- [Summary](#summary)
- [Filename](#filename)
- [Components](#components)
  - [Mandatory](#mandatory)
  - [Optional](#optional)
- [Misc](#misc)
- [Logic](#logic)
  - [detection](#detection)
  - [condition](#condition)
- [Enhancement](#enhancement)

# Filename

* Must be a valid yaml
* Must be unique
* Length between 10 and 70 characters, lowercase and no special characters only letters (a-z) and digits (0-9) are allowed.
* Use `_` instead of a space
* Use `.yml` as a file extension
* Encoding must be UTF-8
* End of line sequence must be LF (Note that windows native editor uses CR-LF)

# Components

## Mandatory

* `title` must be the first line
* `title` must be less than 70 characters
* `title` can not start by "Detects" or finish by a "."
* `title` can use lowercase form for the following  articles
  * 'the'
  * 'for'
  * 'in'
  * 'with'
  * 'via'
  * 'on'
  * 'to'
  * 'without'
  * 'of'
  * 'through'
  * 'from'
  * 'by'
  * 'as'
  * 'a'
  * 'or'
  * 'at'
  * 'and'
  * 'an'
  * 'over'
  * 'new'
* `id` must be a valid uuidv4
* `id` must be unique across all the rules (duplicate id's are not allowed)
* `date` must be follow the format `yyyy/mm/dd` and be valid
* `description` must be a string of at least 16 characters
* `level` must have a valid value (see specification for more information)
* `logsource` must have valid field (see specification for more information)
* `logsource` field must be a string

## Optional

* `tags` must conform to [Tags v1.0.0](Tags_1_0_0.md)
* Mitre tags must be valid  https://attack.mitre.org/
* `tags` value must be unique
* `status` must have a valid value
* `modified` must be follow the format `yyyy/mm/dd` and be valid
* `fields` must be a list
* `falsepositives` must be a list and start with a capital letter
* `falsepositives` can not be "none" or "pentest" or "penetration test"
* `author` must be a string
* tlp must be valid https://www.cisa.gov/tlp
* license must be a string
* target must be a list
* `related` must be a list
* `related` must have a valid value
* `related` must have a valid id/type pair
* `references` must be a list

#  Misc

* There must be no trademark to avoid legal issues
* Spaces are not allowed in field name.
* reference must not exist

# Logic

## detection

* filter name must be unique
* Lists must have more than 1 element
* Must be unique in all files
* `Source: Eventlog` can not be use
* Sysmon Event ID 1 or Security-Auditing Event ID 4688 can not be used instead of `process_creation` category
* Rule with sysmon service in logsource must have a EventID selection
* modifier must
  * `contains`
  * `startswith`
  * `endswith`
  * `all`
  * `base64offset`
  * `base64`
  * `utf16le`
  * `utf16be`
  * `wide`
  * `utf16`
  * `windash`
  * `re`
* `all` modifier can not be used in a single value list
* `ServiceFilename`, `TargetFileName`, `SourceFileName`, `Commandline`, `Targetobject` must not be used
  
## condition

* '1/all of them' must have more than one condition
* 'all of them' is deprecated and must not be used
* 'or','and','not','of' must be lowercase
* all the selections must be used in the condition

# Enhancement

Warning message only

* There are rules that match using localized user accounts. Better employ a generic version

```yaml
    User|contains: # covers many language settings\n" +
        - 'AUTHORI'
        - 'AUTORI'
```
