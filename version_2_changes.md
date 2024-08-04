The following is a non-exhaustive list of changes between the v1 and v2 specification.

# Sigmac

As of August 1st 2024 the `sigmac` toolchain has reached it's end of life, and its corresponding [repository](https://github.com/SigmaHQ/legacy-sigmatools) has been archived. The `sigmac` toolchain doesn't take into account new feature introduced in the second version specification.

The `pySigma` library and it's corresponding command line interface `sigma-cli`, provide full support for version 2 of the specification.

# Date

The latest version of the specification drops support for the date format using a slash `/` separator (YYYY/MM/DD), and now it only recommend the usage of the ISO 8601 format with the a `-` separator (YYYY-MM-DD).

# Modifiers

The latest version of the specification and by extension the `pySigma` library, introduces a new set of modifier. You can check the full list of all supported modifiers in the [modifiers appendix](./appendix/appendix_modifiers.md).

# Correlation

The latest version of the specification drops the usage of the old aggregation expression, in favour of a new format titles meta rules. Check out the [Sigma Meta Rules Specification](/sigma_meta_rules.md) files for a detailed description of the format.

# Sigma Filters

Check out the [Sigma Meta Filter Specification](/Sigma_meta_filter.md) for a detailed description of the format.
