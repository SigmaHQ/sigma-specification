# Sigma-Specification

This repository is used to maintain the specification for the Sigma format.

[Web version](https://sigmahq.github.io/sigma-specification/)

## Version Management

The version number is in the form of 3 digits 'A.B.C':

- 'A' A major version that could break existing converters
- 'B' A minor version with additions or modifications of functionality affecting but not breaking the converters
- 'C' Reorganization of section, addition of examples etc.

## Current Version

The Sigma format specifications is described in the file [Sigma_specification](Sigma_specification.md)  

There exists two other files in the repository to describe the different fields and tags to be used in Sigma rules:

- [Tags_specification](Tags_specification.md) is a document that defines the standardized tags that can be used to categorize the different Sigma rules.
- [Taxonomy_specification](Taxonomy_specification.md) is a document that defines the different field names and log sources that should be used to ensure sharable rules

## Work in Progress

This section lists upcoming developments and changes to the standard. Please note:

- That it's still in a process of dictation and feedback.  
- It is possible that some are added and then deleted before the finalization of the version.  

Do not hesitate to open a discussion with tag `V2` in the title. Example `V2 proposal of new modifier X`.  

For more information, check the [version_2 branch](https://github.com/SigmaHQ/sigma-specification/tree/version_2)

## Archive of Old Specifications

Local copy [sigmahq Specification wiki 2022/09/24](archives/wiki.md) or the online [sigmahq Specification wiki](https://github.com/SigmaHQ/sigma/wiki/Specification)

## SigmaHQ

The following files are not part of the sigma specification. They are only helpers for the management of the main [rule repository](https://github.com/SigmaHQ/sigma/tree/master/rules)

[SigmaHQ Filename Normalisation](sigmahq/Sigmahq_filename_rule.md)
