# Sigma Tags <!-- omit in toc -->

The following document defines the standardized tags that can be used to categorize the different Sigma rules.

* Version 2.1.0
* Release date 2024-08-11

## Summary

- [Summary](#summary)
- [Namespaces](#namespaces)
  - [Namespace: attack](#namespace-attack)
  - [Namespace: car](#namespace-car)
  - [Namespace: cve](#namespace-cve)
  - [Namespace: d3fend](#namespace-d3fend)
  - [Namespace: detection](#namespace-detection)
  - [Namespace: stp](#namespace-stp)
  - [Namespace: tlp](#namespace-tlp)
  - [namespace: detection](#namespace-detection)
- [History](#history)

## Namespaces

* attack: Categorization according to [MITRE ATT&CK](https://attack.mitre.org). To get the current supported version of ATT&CK please visit [MITRE CTI](https://github.com/mitre/cti)
* car: Link to the corresponding [MITRE Cyber Analytics Repository (CAR)](https://car.mitre.org/)
* cve: Categorization according [MITRE CVE](https://cve.mitre.org/)
* d3fend: Categorization according to [MITRE D3FEND](https://d3fend.mitre.org/). To get the current supported version of D3FEND please visit [D3FEND Ontology](https://github.com/d3fend/d3fend-ontology)
* detection: Categorization according to the types of rules provided in the [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma).
* stp: Rating of detection analytic robustness according to the [MITRE Summiting the Pyramid](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/) scheme.
* tlp: [Traffic Light Protocol](https://www.first.org/tlp/).

### Namespace: attack

* t*1234*: Refers to a [technique](https://attack.mitre.org/wiki/All_Techniques)
* g*1234*: Refers to a [group](https://attack.mitre.org/wiki/Groups)
* s*1234*: Refers to [software](https://attack.mitre.org/wiki/Software)

Tactics:

* initial-access: [Initial Access](https://attack.mitre.org/tactics/TA0001/)
* execution: [Execution](https://attack.mitre.org/tactics/TA0002/)
* persistence: [Persistence](https://attack.mitre.org/tactics/TA0003/)
* privilege-escalation: [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
* defense-evasion: [Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
* credential-access: [Credential Access](https://attack.mitre.org/tactics/TA0006/)
* discovery: [Discovery](https://attack.mitre.org/tactics/TA0007/)
* lateral-movement: [Lateral_Movement](https://attack.mitre.org/tactics/TA0008/)
* collection: [Collection](https://attack.mitre.org/tactics/TA0009/)
* exfiltration: [Exfiltration](https://attack.mitre.org/tactics/TA0010/)
* command-and-control: [Command and Control](https://attack.mitre.org/tactics/TA0011/)
* impact: [Impact](https://attack.mitre.org/tactics/TA0040/)

### Namespace: car

Use the CAR tag from MITRE [analytics repository](https://car.mitre.org/analytics/) without the prepending `CAR-`. Example
tag: `car.2016-04-005`.

### Namespace: cve

Use the CVE tag from [MITRE](https://cve.mitre.org) in lower case separated by dots. Example tag: `cve.2021-44228`.

### Namespace: d3fend

[D3FEND](https://d3fend.mitre.org/) is a knowledge base, and more specifically a knowledge graph, of cybersecurity countermeasure techniques.
It is a catalog of defensive cybersecurity techniques and their relationships to offensive/adversary techniques.

* d3-**abc**: Refers to a [technique](https://d3fend.mitre.org/)
* d3f-**abc**: Refers to an [artifact](https://d3fend.mitre.org/dao/artifact/)

For example:

* `d3fend.d3-am`: [Access Modeling](https://d3fend.mitre.org/technique/d3f:AccessModeling/)
* `d3fend.d3f-WindowsNtOpenFile`: [Windows NtOpenFile](https://d3fend.mitre.org/dao/artifact/d3f:WindowsNtOpenFile/)

Tactics:

* model: [Model](https://d3fend.mitre.org/tactic/d3f:Model/)
* harden: [Harden](https://d3fend.mitre.org/tactic/d3f:Harden/)
* detect: [Detect](https://d3fend.mitre.org/tactic/d3f:Model/)
* isolate: [Isolate](https://d3fend.mitre.org/tactic/d3f:Isolate)
* deceive: [Deceive](https://d3fend.mitre.org/tactic/d3f:Deceive)
* evict: [Evict](https://d3fend.mitre.org/tactic/d3f:Evict)

### Namespace: detection

Use the detection tag to indicate the type of a rule. Example tag: `detection.threat-hunting`.

The following tags are currently supported:

* `detection.dfir`
* `detection.emerging-threats`
* `detection.threat-hunting`

### Namespace: stp

The [Summiting the Pyramid](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/) scheme created
by MITRE defines two score dimensions for scoring of the robustness:

* *Analytic robustness* between 1 and 5.
* *Event robustness* as **A**pplication, **U**ser-mode and **K**ernel-mode in ascending order of robustness-

Details for both dimensions are [defined here](https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/levels/).

The *stp* namespace allows to score the robustness of the detection implemented by a Sigma rule according to this
scheme. Because the event robustness depends on the event log source that is an environmental property, Sigma allows to
specify the robustness in the following ways:

* *analytic-only* defines just the analytic robustness in a tag like `stp.4`. This is usually appropriate for generic
  log sources like *process_creation* where it isn't possible to anticipate the robustness of the final log source.
* *complete* defines the whole score in a tag like `stp.3k`. Such a tag should be chosen if the detection refers to a
  concrete log source.

### Namespace: tlp

All TLP levels defined by the [FIRST TLP-SIG](https://www.first.org/tlp/) in lower case. Example tag: `tlp.amber`.

The following tags are currently supported:

* `tlp.red`
* `tlp.amber`
* `tlp.amber-strict`
* `tlp.green`
* `tlp.clear`

## History

* 2024-08-11 Tags Appendix v2.1.0
  * Add mitre d3fend namespace
* 2024-08-08 Tags Appendix v2.0.0
* 2023-11-23 Tags Appendix v1.2.0
  * Add Summiting the Pyramid
* 2023-06-20 Tags Appendix v1.1.0
  * Add detection namespace
* 2022-12-19 Tags Appendix v1.0.1
  * Minor updates and tweaks
* 2022-09-18 Tags Appendix v1.0.0
  * Initial formalization from the sigma wiki
* 2017 Sigma creation
