# Sigma Specification - Generic Signature Format for SIEM Systems

<a href="https://sigmahq.io/">
<p align="center">
<br />
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./media/images/sigma_logo_dark.png">
  <img width="454" alt="Sigma Logo" src="./media/images/sigma_logo_light.png">
</picture>
</p>
</a>
<br />

<p align="center">
<a href="https://sigmahq.io/"><img src="https://cdn.jsdelivr.net/gh/SigmaHQ/sigmahq.github.io@master/images/Sigma%20Official%20Badge.svg" alt="Sigma Official Badge"></a> <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/SigmaHQ/sigma-specification">
<br />
<a href="https://opensourcesecurityindex.io/" target="_blank" rel="noopener">
<img style="width: 170px;" src="https://opensourcesecurityindex.io/badge.svg" alt="Open Source Security Index - Fastest Growing Open Source Security Projects" width="170" />
</a>
</p>

Welcome to the official Sigma Specification repository.

## A Quick Rundown

Here's what you can expect from each of the main subfolders within this repo. Please take a minute to educate yourself!

### Specification

[Specification](./specification/) will contain markdown files describing the Sigma specification format in details. Appendix files providing additional details to certain fields of a Sigma rule

- [Sigma Rules Specification](./specification/sigma-rules-specification.md) - Describes what constitute a Sigma rule.

- [Sigma Correlation Specification](./specification/sigma-correlation-rules-specification.md) - Describes the Sigma correlation format.

- [Sigma Filters Specification](./specification/sigma-filters-specification.md) - Described the Sigma filters format.

- [Sigma Modifiers Appendix](./specification/sigma-appendix-modifiers.md) is a document that defines the different modifiers that can be used in a Sigma rule.

- [Sigma Tags Appendix](./specification/sigma-appendix-tags.md) is a document that defines the tags namespaces that can be used to categorize the different Sigma rules.

- [Sigma Taxonomy Appendix](./specification/sigma-appendix-taxonomy.md) is a document that defines the different field names and log sources that are currently supported by SigmaHQ in order to ensure sharable rules.

- [Sigma Custom Taxonomy Appendix](./specification/sigma-appendix-custom-taxonomy.md) is a document that defines the different field names and log sources that use a taxonomy other than sigma.

### JSON Schema

[Json-Schema](./json-schema/) will contain a list of JSON schemas for the following.

- [Sigma Rules](./json-schema/sigma-detection-rule-schema.json)
- [Sigma Correlation Rules](./json-schema/sigma-correlation-rules-schema.json)
- [Sigma Filters](./json-schema/sigma-filters-schema.json)

### SigmaHQ

[SigmaHQ](./sigmahq/) will contain markdown files that describe rules and recommendations that are applied to the rules hosted in SigmaHQ main rule repository.

> [!NOTE]
> The SigmaHQ folder and the files contains within are not part of the sigma specification. They are there to ensure and easier management of the rules hosted in the main [rule repository](https://github.com/SigmaHQ/sigma/tree/master/rules)

- [SigmaHQ Rule Convention](./sigmahq/sigmahq-rule-convention.md)
- [SigmaHQ Filename Convention](./sigmahq/sigmahq-filename-convention.md)
- [SigmaHQ Title Convention](./sigmahq/sigmahq-title-convention.md)

## Version 2 Changes

You can read more on the potential breaking changes and additional features introduced in version 2.0.0 of the specification [here](./other/version-2-changes.md)
