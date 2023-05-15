# Modifiers <!-- omit in toc -->

The following document defines the standardized modifiers that can be used in Sigma.


* Version 1.0.0
* Release date 2022/12/19


* `all`: Normally, lists of values are linked with *OR* in the generated query. This modifier
  changes this to *AND*. This is useful if you want to express a command line invocation with different
  parameters where the order may vary and removes the need for some cumbersome workarounds.
  
  Single item values are not allowed to have an `all` modifier as some back-ends cannot support it.
  If you use it as a workaround to duplicate a field in a selection, use a new selection instead.
  
* `cased`: Values are applied case sensitively. Default Sigma behaviour is case-insensitive matching.
  
  
* `re`: value is handled as a regular expression by backends. Regex is matched case-sensitive by default
  * `i`: `re` sub-modifier to enable case-sensitive matching

* `cidr`: The value is handled as an CIDR by backends

* `lt`: Field is less than the value
* `lte`: Field is less or equal than the value
* `gt`: Field is greater than the value
* `gte`: Field is greater or equal than the value
* `exists`: that allows to define that a certain field exists or doesn't exists in a log event by providing a boolean value.


* `startswith`: The value is expected at the beginning of the field's content. (replaces e.g. 'adm*')
* `endswith`: The value is expected at the end of the field's content (replaces e.g. '*\cmd.exe')
* `contains`: puts `*` wildcards around the values, such that the value is matched anywhere in the
  field.
  

* `base64`: The value is encoded with Base64.
* `base64offset`: If a value might appear somewhere in a base64-encoded string the representation
  might change depending on the position of the value in the overall string. There are three variants for shifts
  by zero to two bytes and except the first and last byte the encoded values have a static part in
  the middle that can be recognized.

* `utf16le`: Transforms value to UTF16-LE encoding, e.g. `cmd` > `63 00 6d 00 64 00` (only used in combination with base64 modifiers)
* `utf16be`: Transforms value to UTF16-BE encoding, e.g. `cmd` > `00 63 00 6d 00 64` (only used in combination with base64 modifiers)
* `wide`: Alias for `utf16le` modifier
* `utf16`: Prepends a [byte order mark](https://en.wikipedia.org/wiki/Byte_order_mark) and encodes UTF16, e.g. `cmd` > `FF FE 63 00 6d 00 64 00` (only used in combination with base64 modifiers)

* `windash`: creates all possible permutations of the `-` and `/` characters. Windows command line flags can often be indicated by both characters. Using the `windash` modifier converts `-` values into `/` and vice versa and uses all possible permutation of strings in the selection.

* `expand`: Modifier for expansion of placeholders in values. The final behavior of the replacement is determined by processing pipeline transformations. Current possibilities in pySigma are:
  * Expand to value list (`ValueListPlaceholderTransformation`/`value_placeholders`)
  * Replace with query expression in target query language (`QueryExpressionPlaceholderTransformation`/`query_expression_placeholders`)
  * Replace placeholder with wildcard `*`, which should only be used as last resort. (`WildcardPlaceholderTransformation`/`wildcard_placeholders`)


