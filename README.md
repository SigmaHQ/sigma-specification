# Sigma Specification - Generic Signature Format for SIEM Systems

<a href="https://sigmahq.io/">
<p align="center">
<br />
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./images/sigma_logo_dark.png">
  <img width="454" alt="Sigma Logo" src="./images/sigma_logo_light.png">
</picture>
</p>
</a>
<br />

<p align="center">
<a href="https://sigmahq.io/"><img src="https://cdn.jsdelivr.net/gh/SigmaHQ/sigmahq.github.io@master/images/Sigma%20Official%20Badge.svg" alt="Sigma Official Badge"></a> <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/SigmaHQ/sigma">
<img alt="GitHub all releases" src="https://img.shields.io/github/downloads/SigmaHq/Sigma/total">
<br />
<a href="https://opensourcesecurityindex.io/" target="_blank" rel="noopener">
<img style="width: 170px;" src="https://opensourcesecurityindex.io/badge.svg" alt="Open Source Security Index - Fastest Growing Open Source Security Projects" width="170" />
</a>
</p>

Welcome to the Sigma specification repository

## Version Management

The version number is in the form of 3 digits 'A.B.C':

- 'A' A major version that could break existing converters
- 'B' A minor version with additions or modifications of functionality affecting but not breaking the converters
- 'C' Reorganization of section, addition of examples etc.

## Current Version

The Sigma rules format specifications is described in the file [Sigma_specification](Sigma_specification.md)  
The Sigma Meta rules format specifications is described in the file [Sigma_meta_rules](Sigma_meta_rules.md)  
The Sigma Meta filter format specifications is described in the file [Sigma_meta_filter](Sigma_meta_filter.md)  

There exists other files in the repository to describe the different modifiers, fields and tags to be used in Sigma rules:

- [appendix_modifier](appendix/appendix_modifier.md) is a document that defines the different modifiers that can be used in a Sigma rule. 
- [appendix_tags](appendix/appendix_tags.md) is a document that defines the standardized tags that can be used to categorize the different Sigma rules.
- [appendix_taxonomy](appendix/appendix_taxonomy.md) is a document that defines the different field names and log sources that should be used to ensure sharable rules.

## SigmaHQ

The following files are not part of the sigma specification. 
They are only helpers for the management of the main [rule repository](https://github.com/SigmaHQ/sigma/tree/master/rules) under SigmaHQ

[SigmaHQ Filename Normalisation](/sigmahq/Sigmahq_filename_rule.md)
[SigmaHQ Rule Conventions](/sigmahq/sigmahq_conventions.md)
[SigmaHQ Title Normalisation](/sigmahq/sigmahq_title_rule.md)
