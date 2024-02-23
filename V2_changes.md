The following is a non-exhaustive list of changes between the v1 and v2 specifications.


# Sigmac

Warning `sigmac` will not be able to convert all the specification of this version. \
Only `pySigma` and the corresponding `sigma-cli` provide full support for version 2.

# Date

Legacy sigma rule use YYYY/MM/DD or YYYY-MM-DD format for the date. \
Version 2 only use ISO 8601 with separator format : YYYY-MM-DD

# New Modifiers

- `windash` : creates all possible permutations of the `-` and `/` characters. Windows command line flags can often be indicated by both characters. Using the `windash` modifier converts `-` values into `/` and vice versa and uses all possible permutation of strings in the selection. This will be used for all `CommandLine` fields in windows > `process_creation` rules.
- `exists` that allows to define that a certain field exists or doesn't exists in a log event by providing
  a boolean value. Currently we use filters with `field: null` as a workaround for this purpose, which is less descriptive.


# Correlation

- Remove aggregation expression in Sigma rule file see [Sigma meta rules](/Sigma_meta_rules.md)

# Global filter

- Adds the ability to make global filters see [Sigma meta filter](/Sigma_meta_filter.md)
