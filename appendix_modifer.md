# Modifiers <!-- omit in toc -->

The following document defines the standardized modifiers that can be used in the Sigma rules.

* Version 1.0.0
* Release date 2022/12/19

# Summary

- [Summary](#summary)
  - [Transformations](#transformations)
  - [Types](#types)


## Transformations

* `contains`: puts `*` wildcards around the values, such that the value is matched anywhere in the
  field.
* `all`: Normally, lists of values were linked with *OR* in the generated query. This modifier
  changes
  this to *AND*. This is useful if you want to express a command line invocation with different
  parameters where the order may vary and removes the need for some cumbersome workarounds.

  Single item values are not allowed to have an `all` modifier as some back-ends cannot support it.
  If you use it as a workaround to duplicate a field in a selection, use a new selection instead.
* `base64`: The value is encoded with Base64.
* `base64offset`: If a value might appear somewhere in a base64-encoded string the representation
  might change depending on the position of the value in the overall string. There are three variants for shifts
  by zero to two bytes and except the first and last byte the encoded values have a static part in
  the middle that can be recognized.
* `endswith`: The value is expected at the end of the field's content (replaces e.g. '*\cmd.exe')
* `startswith`: The value is expected at the beginning of the field's content. (replaces e.g. 'adm*')
* `utf16le`: Transforms value to UTF16-LE encoding, e.g. `cmd` > `63 00 6d 00 64 00` (only used in combination with base64 modifiers)
* `utf16be`: Transforms value to UTF16-BE encoding, e.g. `cmd` > `00 63 00 6d 00 64` (only used in combination with base64 modifiers)
* `wide`: Alias for `utf16le` modifier
* `utf16`: Prepends a [byte order mark](https://en.wikipedia.org/wiki/Byte_order_mark) and encodes UTF16, e.g. `cmd` > `FF FE 63 00 6d 00 64 00` (only used in combination with base64 modifiers)
* `windash`: Add a new variant where all `-` occurrences are replaced with `/`. The original variant is also kept unchanged.
* `cidr`: The value is handled as an IPv4 CIDR by backends (IPv6 is not supported, yet)
* `lt`: Field is less than the value
* `lte`: Field is less or egal than the value
* `gt`: Field is Greater than the value
* `gte`: Field is Greater or egal than the value
* `expand`: Modifier for expansion of placeholders in values. It replaces placeholder strings

## Types

* `re`: value is handled as regular expression by backends. Currently, this is only supported by
  the Elasticsearch query string backend (*es-qs*). Further (like Splunk) are planned or have
  to be implemented by contributors with access to the target systems.