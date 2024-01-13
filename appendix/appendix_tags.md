# Tags <!-- omit in toc -->

The following document defines the standardized tags that can be used to categorize the different Sigma rules.

* Version 1.2.0
* Release date 2023-11-23

## Summary

- [Summary](#summary)
- [Namespaces](#namespaces)
  - [Namespace: attack](#namespace-attack)
  - [Namespace: car](#namespace-car)
  - [Namespace: stp](#namespace-stp)
  - [Namespace: cve](#namespace-cve)
  - [Namespace: tlp](#namespace-tlp)
  - [namespace: detection](#namespace-detection)
- [History](#history)

## Namespaces

* attack: Categorization according to [MITRE ATT&CK](https://attack.mitre.org). To get the current supported version of ATT&CK please visite [MITRE CTI](https://github.com/mitre/cti)
* car: Link to the corresponding [MITRE Cyber Analytics Repository (CAR)](https://car.mitre.org/)
* stp: Rating of detection analytic robustness according to the [MITRE Summiting the Pyramid](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/) scheme.
* tlp: [Traffic Light Protocol](https://www.first.org/tlp/)

### Namespace: attack

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

### Namespace: car

Use the CAR tag from the [analytics repository](https://car.mitre.org/analytics/) without the prepending `CAR-`. Example
tag: `car.2016-04-005`.

### Namespace: stp

The [Summiting the Pyramid](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/) scheme created
by MITRE defines two score dimensions for scoring of the robustness:

* *Analytic robustness* between 1 and 5.
* *Event robustness* as **A**pplication, **U**ser-mode and **K**ernel-mode in ascending order of robustness-

Details for both dimensions are [defined here](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/levels/).

The *stp* namespace allows to score the robustness of the detection implemented by a Sigma rule according to this
scheme. Because the event robustness depends on the event log source that is an enviromental property, Sigma allows to
specify the robustness in the following ways:

* *analytic-only* defines just the analytic robustness in a tag like `stp.4`. This is usually appropriate for generic
  log sources like *process_creation* where it isn't possible to anticipate the robustness of the final log source.
* *complete* defines the whole score in a tag like `stp.3k`. Such a tag should be chosen if the detection refers to a
  concrete log source.

### Namespace: cve

Use the CVE tag from the [mitre](https://cve.mitre.org) in lower case seperated by dots. Example tag: `cve.2021.44228`.

### Namespace: tlp

All TLP levels defined by the [FIRST TLP-SIG](https://www.first.org/tlp/) in lower case. Example tag: `tlp.amber`.

### namespace: detection

Use the detection tag to indicate the type of a rule. Example tag: `detection.threat_hunting`.

* dfir
* emerging_threats
* threat_hunting 

## History
* 2023-11-23 Tags V1.2.0
  * Add Summiting the Pyramid
* 2023-06-20 Tags V1.1.0
  * Add detection namespace
* 2022-12-19 Tags V1.0.1
  * Minor updates and tweaks
* 2022-09-18 Tags V1.0.0
  * Initial formalisation from the sigma wiki
* 2017 Sigma creation
