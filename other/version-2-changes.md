# Changes and Feature Introduced in V2.0.0

The following is a non-exhaustive list of changes between the v1 and v2 specification.

## Sigmac

As of August 1st 2024 the `sigmac` toolchain has reached it's end of life, and its corresponding [repository](https://github.com/SigmaHQ/legacy-sigmatools) has been archived. The `sigmac` toolchain doesn't take into account new feature introduced in the second version specification.

The `pySigma` library and it's corresponding command line interface `sigma-cli`, provide full support for version 2 of the specification.

## Date & Modified Field

The latest version of the specification drops support for the date format using a slash `/` separator (YYYY/MM/DD), and now it only recommend the usage of the ISO 8601 format with the a `-` separator (YYYY-MM-DD).

## Tags Field

The latest version of the specification changed the use of "underscore" and "dots" in favour of "dashes" for the following tag namespaces:

* ATT&CK
* CVE
* Detection

## Related Field

The related field type `obsoletes` has been changed to `obsolete` for consistency purposes.

## Rx Schema

The latest version of the specification drops the support for the [Rx-Schema](https://github.com/SigmaHQ/sigma-specification/blob/69ce07a4068a9668098eef148ab874862625bbeb/archives/wiki.md#rx-yaml) in favour of a [JSON schema](/json-schema/).

## Modifiers

The latest version of the specification and by extension the `pySigma` library, introduces a new set of modifier. You can check the full list of all currently supported modifiers in the [Sigma Modifiers Appendix](./appendix/sigma-modifiers-appendix.md).

## Correlation

The latest version of the specification drops the usage of the old aggregation expression, in favour of a new format titled meta/correlation rules. Check out the [Sigma Correlation Rules Specification](/specification/sigma-correlation-rules-specification.md) for full details.

## Sigma Filters

Check out the [Sigma Filters Specification](/specification/sigma-filters-specification.md) for a detailed description of the format.
