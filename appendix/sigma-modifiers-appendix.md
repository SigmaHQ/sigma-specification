# Modifiers <!-- omit in toc -->

The following document defines the standardized modifiers that can be used in Sigma.

* Version 2.0.0
* Release date 2024-08-08

## Summary
- [Summary](#summary)
- [General](#general)
  - [String only](#string-only)
  - [Numeric only](#numeric-only)
  - [Ip only](#ip-only)
  - [String Encoding](#string-encoding)
- [Specific](#specific)
- [History](#history)

## General

* `all`: Normally, lists of values are linked with *OR* in the generated query. This modifier
  changes this to *AND*. This is useful if you want to express a command line invocation with different
  parameters where the order may vary and removes the need for some cumbersome workarounds.
  
  Single item values are not allowed to have an `all` modifier as some back-ends cannot support it.
  If you use it as a workaround to duplicate a field in a selection, use a new selection instead.

* `startswith`: The value is expected at the beginning of the field's content. (replaces e.g. 'adm*')
* `endswith`: The value is expected at the end of the field's content (replaces e.g. '*\cmd.exe')
* `contains`: Puts `*` wildcards around the values, such that the value is matched anywhere in the
  field.

* `exists`: Defines that a certain field has to exist or must not exist in a log event by providing a boolean value. Note that this check only verifies the presence of a field, not its value, be it empty or null.
* `cased`: Values are applied case sensitively. Default Sigma behavior is case-insensitive matching.

### String only

* `windash`: Creates all possible permutations of the `-`, `/`, `–` (en dash), `—` (em dash), and `―` (horizontal bar) characters. Windows command line flags can often be indicated by both characters. Using the `windash` modifier converts the aforementioned characters interchangeably and uses all possible permutation of strings in the selection.

* `re`: Value is handled as a regular expression by backends. Regex is matched case-sensitive by default
* `re` sub-modifiers:
  * `i`: (insensitive) to enable case-insensitive matching.
  * `m`: (multi line) to match across multiple lines. `^` /`$` match the start/end of line.
  * `s`: (single line) to enable that dot (`.`) matches all characters, including the newline character.

### Numeric only

* `lt`: Field is less than the value
* `lte`: Field is less or equal than the value
* `gt`: Field is greater than the value
* `gte`: Field is greater or equal than the value

### Ip only
  
* `cidr`: The value is handled as an CIDR by backends. Supports both IPv4 and IPv6 notations.

### String Encoding

* `base64`: The value is encoded with Base64.
* `base64offset`: If a value might appear somewhere in a base64-encoded string the representation
  might change depending on the position of the value in the overall string. There are three variants for shifts
  by zero to two bytes and except the first and last byte the encoded values have a static part in
  the middle that can be recognized.

* `base64` sub-modifiers:
  * `utf16le`: Transforms value to UTF16-LE encoding, e.g. `cmd` > `63 00 6d 00 64 00` 
  * `utf16be`: Transforms value to UTF16-BE encoding, e.g. `cmd` > `00 63 00 6d 00 64`
  * `utf16`: Prepends a [byte order mark](https://en.wikipedia.org/wiki/Byte_order_mark) and encodes UTF16, e.g. `cmd` > `FF FE 63 00 6d 00 64 00`

## Specific

* `expand`: Modifier for expansion of placeholders in values. The final behavior of the replacement is determined by processing pipeline transformations. Current possibilities in pySigma are:
  * Expand to value list (`ValueListPlaceholderTransformation`/`value_placeholders`)
  * Replace with query expression in target query language (`QueryExpressionPlaceholderTransformation`/`query_expression_placeholders`)
  * Replace placeholder with wildcard `*`, which should only be used as last resort. (`WildcardPlaceholderTransformation`/`wildcard_placeholders`)

* `fieldref`: Modifies a plain string into a field reference. A field reference can be used to compare fields of matched
  events directly at query/matching time.

## History

* 2024-08-08 Modifiers Appendix v2.0.0
* 2023-05-27 Modifiers Appendix v1.0.4
  * Update from PySigma 0.7.6
  * Add `fieldref`
* 2023-05-21 Modifiers Appendix v1.0.3
  * Creation of the file
* 2017 Sigma creation
