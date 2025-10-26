# SigmaHQ Regression Testing Conventions

This document describes an additional set of custom rules field enforced by the SigmaHQ rule repository in order to ensure a better quality of rules as well as their reproduction.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [SigmaHQ Regression Testing Conventions](#sigmahq-regression-testing-conventions)
  - [Custom Fields](#custom-fields)
    - [`regression_tests_path` Field](#regression_tests_path-field)
      - [Info.yml Structure](#infoyml-structure)
        - [id](#id)
        - [description](#description)
        - [date](#date)
        - [modified](#modified)
        - [author](#author)
        - [rule\_metadata](#rule_metadata)
        - [regression\_tests\_info](#regression_tests_info)
    - [`simulation` Field](#simulation-field)
      - [Atomic Red Team Entry Structure](#atomic-red-team-entry-structure)

<!-- mdformat-toc end -->

## Custom Fields

SigmaHQ rules extend the specification defined in the [Sigma Rule Specification](../specification/sigma-rules-specification.md) by adding the following custom fields for regression testing purposes:

- `regression_tests_path`
- `simulation`

Below is a detailed description of each field and its structure and purpose.

### `regression_tests_path` Field

The `regression_tests_path` field is used to specify the path to the regression tests associated with the rule. This field helps in organizing and locating the tests for each rule as well ease of automation in the testing process.

The path should point to an `info.yml` that will be located in a mirror file directory to the rule itself in the `regression_data` folder and without the `.yml` extension. For example, if the rule is located at:

```yaml
rules/windows/process_creation/win_suspicious_process_creation.yml
```

Then the corresponding `regression_tests_path` should be:

```yaml
regression_tests_path: regression_data/windows/process_creation/win_suspicious_process_creation/info.yml
```

This file will contain the necessary information for executing the regression tests for the rule.

The `regression_data` folder should mirror the structure of the `rules` folder to maintain consistency and ease of navigation.

Inside each rule's corresponding folder in `regression_data` there should:

- An `info.yml` file containing metadata about the regression tests.
- One or more test data files (e.g., `.evtx`, `.json`, `.log`, etc.) that will be used for testing the rule.

#### Info.yml Structure

The `info.yml` file should have the following structure:

```yaml
id [required]
description [required]
date [required]
modified [optional]
author [required]
rule_metadata:
    - id [required]
      title [required]
regression_tests_info:
    - name [required]
      type [required]
      provider [required]
      match_count [required]
      path [required]

```

##### id

The `id` field is used to uniquely identify the regression test information file. This identifier helps in tracking and referencing the specific set of regression tests associated with a rule.

##### description

The `description` field provides a brief overview of the tests contained within the `info.yml` file. This description helps in understanding the purpose and scope of the regression tests defined for the rule.

##### date

The `date` field indicates when the regression test information file was created.

##### modified

The `modified` field indicates the last date when the regression test information file was updated.

##### author

The `author` field specifies the individual or team responsible for creating the regression test information file.

##### rule_metadata

The `rule_metadata` section contains a list of metadata entries for the rule, including:

- `id`: The unique identifier for the rule.
- `title`: The title of the rule.

##### regression_tests_info

The `regression_tests_info` section contains a list of regression test entries, each with the following fields:

- `name`: The name of the regression test. Can be anything that helps identify the test. For example: "Sysmon Test Data".
- `type`: The type of regression test (e.g., evtx, splunk, elastic, sql).
- `provider`: The source or provider of the test data. For example: "Windows-Microsoft-Sysmon".
- `match_count`: The expected number of matches for the test. For most cases, this will be `1`. Except for correlation type rules or cases where we want all condition to be matched
- `path`: The path to the test data file.

### `simulation` Field

The `simulation` field is a list of entries that describe different simulation or emulation frameworks tests. Currently the only format supported is for the `Atomic Red Team` framework. Additional formats such as `Caldera` will be added in the future.

#### Atomic Red Team Entry Structure

Each entry in the `simulation` list for Atomic Red Team should have the following structure:

```yaml
simulation:
    - type [required]
      name [required]
      technique [required]
      atomic_guid [required]
```

- `type`: The type of simulation framework. For Atomic Red Team, this should be `atomic-red-team`.
- `name`: The name of the Atomic Red Team test.
- `technique`: The MITRE ATT&CK technique identifier associated with the test (e.g., `T1059`).
- `atomic_guid`: The unique identifier for the Atomic Red Team test (e.g., `d4f6b8c2-3e5b-4c1a-9f3b-2c3e4f5a6b7c`).
