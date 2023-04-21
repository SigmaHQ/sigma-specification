**Breaking changes**


Warning `sigmac` will not be able to convert this version. Only `pySigma` and the corresponding `sigma-cli` provide full support for version 2.


# New Modifier

- `windash` : converts `-` values into `/` and vice versa. Will be used for all `CommandLine` fields in windows > `process_creation` rules.
- `exists` that allows to define that a certain field exists or doesn't exists in a log event by providing
  a boolean value. Currently we use filters with `field: null` as a workaround for this purpose, which is inaccurate.

# Corelation

- Remove aggregation expression in sigma rule file see [Sigma meta rules](Sigma_meta_rules.md)