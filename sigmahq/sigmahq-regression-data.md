# SigmaHQ Regression Data Specification

This document describes the specification for regression test data in the SigmaHQ repository. Regression tests ensure that Sigma rules correctly detect their intended events by running them against known log samples stored alongside `info.yml`.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Overview](#overview)
- [Directory Structure](#directory-structure)
- [The `info.yml` File](#the-infoyml-file)
  - [Required Fields](#required-fields)
  - [Field Descriptions](#field-descriptions)
- [Linking Regression Tests to Sigma Rules](#linking-regression-tests-to-sigma-rules)
  - [In the Sigma Rule YAML File](#in-the-sigma-rule-yaml-file)
  - [Path Convention](#path-convention)
- [Test Sample File Naming Convention](#test-sample-file-naming-convention)
- [Test Types](#test-types)
  - [Positive Detection Test](#positive-detection-test)
- [Status Requirements](#status-requirements)
- [Validation](#validation)

<!-- mdformat-toc end -->

## Overview

Regression tests are defined by an `info.yml` file placed alongside log samples in the `regression_data/` directory. The regression test runner (`tests/regression_tests_runner.py`) validates that each Sigma rule produces the expected number of matches against its associated test samples.

## Directory Structure

```
regression_data/
├── rules/
│   ├── windows/
│   │   ├── process_creation/
│   │   │   └── proc_creation_win_cipher_overwrite_deleted_data/
│   │   │       ├── info.yml
│   │   │       └── <rule-id>.<ext>
│   │   ├── registry/
│   │   │   └── registry_set/
│   │   │       └── registry_set_disable_defender_firewall/
│   │   │           ├── info.yml
│   │   │           └── <rule-id>.<ext>
│   │   └── ...
│   ├── process_access/
│   ├── image_load/
│   ├── file/
│   ├── sysmon/
│   ├── builtin/
│   └── cisco/
├── pipelines/
│   └── process_creation_fieldmapping.yml
├── rules-emerging-threats/
│   ├── 2025/
│   │   ├── Exploits/
│   │   ├── Malware/
│   │   └── ...
│   └── 2026/
│       └── Exploits/
└── rules-threat-hunting/
    └── windows/
        └── image_load/
```

`<ext>` is the file extension of the test sample (`evtx` or `json`), determined by the `type` field in `info.yml`.

The `pipelines/` directory holds Sigma conversion pipelines referenced by JSON test entries via the `pipelines` field in `info.yml`.

The directory name under `regression_data/` must match the rule file name stem (without the `.yml` extension). For example, the rule `proc_creation_win_cipher_overwrite_deleted_data.yml` uses the directory `proc_creation_win_cipher_overwrite_deleted_data/`.

The `regression_data/` directory mirrors the `rules/` directory structure: a rule at `rules/windows/process_creation/proc_creation_win_foo.yml` maps to `regression_data/rules/windows/process_creation/proc_creation_win_foo/`.

**Note:** The `regression_data/` path structure mirrors the corresponding rule's location in `rules/` or `rules-emerging-threats/` or `rules-threat-hunting/`. This means the `info.yml` directory name must match the rule file name stem.

## The `info.yml` File

Every regression test directory must contain an `info.yml` file with the following structure:

### Required Fields

```yaml
id: <uuid>                                    # UUID for the regression test entry (different from rule ID)
description: <free-text description or "N/A"> # Human-readable description of the test scenario
date: YYYY-MM-DD                              # Date the regression test was added
author: <Author Name>                         # Author of the regression test
rule_metadata:
    - id: <rule-uuid>                         # Must match the Sigma rule's `id` field exactly
      title: <Rule Title>                     # Must match the Sigma rule's `title` field exactly
regression_tests_info:
    - name: Positive Detection Test           # Test name (use "Positive Detection Test" for positive tests)
      type: evtx                              # Test type: evtx, json, ndjson, or jsonl
      provider: Microsoft-Windows-Sysmon      # Log provider (informational, not used by the runner at the moment)
      match_count: 1                          # Minimum number of matches required. Omit to require at least one match.
      path: regression_data/<path>/<to>/<rule-dir>/<rule-id>.<ext>
```

### Field Descriptions

| Field                                 | Description                                                                                                                                                             |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                                  | A unique UUID for this regression test entry. Different from the rule `id`.                                                                                             |
| `description`                         | Free-text description of what the test verifies. Use `"N/A"` if no description is available.                                                                            |
| `date`                                | ISO date (YYYY-MM-DD) when the regression test was created or last updated.                                                                                             |
| `author`                              | Full name of the author, optionally followed by organization in parentheses.                                                                                            |
| `rule_metadata.id`                    | The Sigma rule UUID. **Must exactly match** the `id` field in the corresponding `.yml` rule file.                                                                       |
| `rule_metadata.title`                 | The Sigma rule title. **Must exactly match** the `title` field in the corresponding `.yml` rule file.                                                                   |
| `regression_tests_info[].name`        | Optional human-readable test name. Use `"Positive Detection Test"` for tests that verify the rule matches. The runner falls back to `Unnamed Test` if omitted.          |
| `regression_tests_info[].type`        | Test type. Supported values: `evtx`, `json`, `ndjson`, `jsonl`.                                                                                                         |
| `regression_tests_info[].provider`    | Windows event provider. Informational only — the runner does not use it at the moment.                                                                                  |
| `regression_tests_info[].match_count` | Minimum number of matches required. If omitted, the runner requires at least one match. If actual count exceeds this value, a warning is emitted rather than a failure. |
| `regression_tests_info[].path`        | Relative path from the repository root to the test sample file.                                                                                                         |
| `regression_tests_info[].pipelines`   | Optional array of paths to Sigma conversion pipelines, applied before the rule is compiled. JSON test types only.                                                       |
| `regression_tests_info[].filters`     | Optional array of paths to Sigma filters, applied during rule compilation. JSON test types only.                                                                        |

## Linking Regression Tests to Sigma Rules

### In the Sigma Rule YAML File

Add the `regression_tests_path` field pointing to the `info.yml` file:

```yaml
title: Deleted Data Overwritten Via Cipher.EXE
id: 4b046706-5789-4673-b111-66f25fe99534
status: test
description: |
    Detects usage of cipher.exe to overwrite deleted files.
author: Author Name
date: 2025-10-24
tags:
    - attack.defense-impairment
    - attack.t1070
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '/w'
            - 'cipher'
    condition: selection
falsepositives:
    - Legitimate disk cleanup operations
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_cipher_overwrite_deleted_data/info.yml
```

### Path Convention

The `regression_tests_path` value is a relative path from the repository root:

- For rules in `rules/windows/`: `regression_data/rules/windows/<category>/<rule-name>/info.yml`
- For rules in `rules-emerging-threats/`: `regression_data/rules-emerging-threats/<year>/<category>/<name>/info.yml`
- For rules in `rules-threat-hunting/`: `regression_data/rules-threat-hunting/<category>/<rule-name>/info.yml`

## Test Sample File Naming Convention

Test sample files are named using the Sigma rule's UUID as the stem:

```
<rule-id>.<ext>
```

The extension depends on the `type` field in `info.yml`:

| `type`   | Expected extension | Example                                     |
| -------- | ------------------ | ------------------------------------------- |
| `evtx`   | `.evtx`            | `4b046706-5789-4673-b111-66f25fe99534.evtx` |
| `json`   | `.json`            | `4b046706-5789-4673-b111-66f25fe99534.json` |
| `ndjson` | `.json`            | `4b046706-5789-4673-b111-66f25fe99534.json` |
| `jsonl`  | `.json`            | `4b046706-5789-4673-b111-66f25fe99534.json` |

For example, for rule `id: 4b046706-5789-4673-b111-66f25fe99534` with `type: evtx`, the file must be:

```
regression_data/rules/windows/process_creation/proc_creation_win_cipher_overwrite_deleted_data/4b046706-5789-4673-b111-66f25fe99534.evtx
```

For `type: json`, `ndjson`, and `jsonl` entries, the test sample is a JSON file named after the rule ID:

```
regression_data/rules/windows/process_creation/proc_creation_win_cipher_overwrite_deleted_data/4b046706-5789-4673-b111-66f25fe99534.json
```

The file contains either a single JSON object (`json`) or one JSON object per line (`ndjson`, `jsonl`).

## Test Types

### Positive Detection Test

Verifies that the Sigma rule correctly matches the provided test sample.

```yaml
regression_tests_info:
    - name: Positive Detection Test
      type: evtx
      provider: Microsoft-Windows-Sysmon
      match_count: 1
      path: regression_data/.../4b046706-5789-4673-b111-66f25fe99534.evtx
    - name: Positive Detection Test
      type: json
      match_count: 1
      pipelines:
          - regression_data/pipelines/process_creation_fieldmapping.yml
      path: regression_data/.../4b046706-5789-4673-b111-66f25fe99534.json
```

**Match count rules:**

- `match_count: 1` — the default for standard positive detection tests. Explicitly setting it is optional.
- `match_count: N` (where N > 1) — used when the test sample contains multiple events that each produce a match, or when the rule's detection logic has multiple conditions that each match once against the sample. Examples:
  - `match_count: 2` — the rule matches twice against the sample (e.g., a rule with two `selection_*` conditions, each triggered by a different event in the same file).
  - `match_count: 4` — four matching events are expected.
  - `match_count: 7` — seven matching events are expected.

**How to determine `match_count`:** Run the regression test runner and read the output. If the actual match count exceeds `match_count`, a warning is emitted showing the actual count — use that value as your new `match_count`.

## Status Requirements

Rules with `status: test` or `status: stable` **must** have a `regression_tests_path` field pointing to a valid `info.yml`. Rules with `status: experimental` or `status: deprecated` are exempt from this requirement but may still include regression tests.

## Validation

The regression test runner (`tests/regression_tests_runner.py`) performs the following validations:

1. **Rule ID consistency**: `rule_metadata[0].id` in `info.yml` must match the `id` field in the Sigma rule YAML.
1. **File naming**: The test sample file name (without extension) must match the rule `id`.
1. **File existence**: All referenced files (`info.yml` and test samples) must exist.
1. **Match count**: The rule must produce at least the expected number of matches against the test sample. If the actual match count exceeds `match_count`, a warning is emitted (rather than a failure) to encourage updating the `info.yml`.
