# Tags <!-- omit in toc -->

This documents defines the standardized tags that can be used to categorize the different Sigma rules.

* Version 1.0.1
* Release date 2022/12/19

History:

* 2022/09/18 Tags V1.0.0
  * Initial formalisation from the sigma wiki
* 2017 Sigma creation

# Summary

- [Summary](#summary)
- [Namespaces](#namespaces)
  - [Namespace: attack](#namespace-attack)
  - [Namespace: car](#namespace-car)
  - [Namespace: cve](#namespace-cve)
  - [Namespace: tlp](#namespace-tlp)

# Namespaces

* attack: Categorization according to [MITRE ATT&CK](https://attack.mitre.org). To get the current supported version of ATT&CK please visite [MITRE CTI](https://github.com/mitre/cti)
* car: Link to the corresponding [MITRE Cyber Analytics Repository (CAR)](https://car.mitre.org/)
* tlp: [Traffic Light Protocol](https://www.first.org/tlp/)

## Namespace: attack

* t*1234*: Refers to a [technique](https://attack.mitre.org/wiki/All_Techniques)
* g*1234*: Refers to a [group](https://attack.mitre.org/wiki/Groups)
* s*1234*: Refers to [software](https://attack.mitre.org/wiki/Software)

Tactics:

* initial_access: [Initial Access](https://attack.mitre.org/tactics/TA0001/)
* execution: [Execution](https://attack.mitre.org/tactics/TA0002/)
* persistence: [Persistence](https://attack.mitre.org/tactics/TA0003/)
* privilege_escalation: [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
* defense_evasion: [Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
* credential_access: [Credential Access](https://attack.mitre.org/tactics/TA0006/)
* discovery: [Discovery](https://attack.mitre.org/tactics/TA0007/)
* lateral_movement: [Lateral_Movement](https://attack.mitre.org/tactics/TA0008/)
* collection: [Collection](https://attack.mitre.org/tactics/TA0009/)
* exfiltration: [Exfiltration](https://attack.mitre.org/tactics/TA0010/)
* command_and_control: [Command and Control](https://attack.mitre.org/tactics/TA0011/)
* impact: [Impact](https://attack.mitre.org/tactics/TA0040/)

## Namespace: car

Use the CAR tag from the [analytics repository](https://car.mitre.org/analytics/) without the prepending `CAR-`. Example tag: `car.2016-04-005`.

## Namespace: cve

Use the CVE tag from the [mitre](https://cve.mitre.org) in lower case seperated by dots. Example tag: `cve.2021.44228`.

## Namespace: tlp

All TLP levels defined by the [FIRST TLP-SIG](https://www.first.org/tlp/) in lower case. Example tag: `tlp.amber`.
