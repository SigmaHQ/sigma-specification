# Sigma-Specification

This repository is used to maintain the specification for the Sigma format.

## Version Management

The version number is in the form of 3 digits 'A.B.C':

- 'A' A major version that could break existing converters
- 'B' A minor version with additions or modifications of functionality affecting but not breaking the converters
- 'C' Reorganization of section, addition of examples etc.

## Current Version

The Sigma rules format specifications is described in the file [Sigma_specification](Sigma_specification.md)  
The Sigma Meta-rules format specifications is described in the file [Sigma_meta_rules](Sigma_meta_rules.md)  

There exists other files in the repository to describe the different modifier, fields and tags to be used in Sigma rules:

- [appendix_modifier](appendix_modifer.md) is a document that defines the different modifier use that can be used in a Sigma rule. 
- [appendix_tags](appendix_tags.md) is a document that defines the standardized tags that can be used to categorize the different Sigma rules.
- [appendix_taxonomy](appendix_taxonomy.md) is a document that defines the different field names and log sources that should be used to ensure sharable rules

## SigmaHQ

The following files are not part of the sigma specification. They are only helpers for the management of the main [rule repository](https://github.com/SigmaHQ/sigma/tree/master/rules)

[SigmaHQ Filename Normalisation](sigmahq/Sigmahq_filename_rule.md)
