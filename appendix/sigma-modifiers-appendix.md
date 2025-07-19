# Sigma Modifiers

The following document defines the standardized modifiers that can be used in Sigma.

- Version 2.1.0
- Release date 2025-07-17

<!-- mdformat-toc start --slug=github --maxlevel=6 --minlevel=2 -->

- [Generic Modifiers](#generic-modifiers)
- [String Modifiers](#string-modifiers)
  - [Regular Expression](#regular-expression)
  - [Encoding](#encoding)
- [Numeric Modifiers](#numeric-modifiers)
- [Time Modifiers](#time-modifiers)
- [IP (Internet Protocol) Modifiers](#ip-internet-protocol-modifiers)
- [Specific Modifiers](#specific-modifiers)
- [History](#history)

<!-- mdformat-toc end -->

### Generic Modifiers<a name="generic-modifiers"></a>

The following modifiers are considered generic modifiers and can be applied on all types of fields.

- `all`: Normally, lists of values are linked with *OR* in the generated query. This modifier
  changes this to *AND*. This is useful if you want to express a command line invocation with different
  parameters where the order may vary and removes the need for some cumbersome workarounds.

  Single item values are not allowed to have an `all` modifier as some back-ends cannot support it.
  If you use it as a workaround to duplicate a field in a selection, use a new selection instead.

- `startswith`: The value is expected at the beginning of the field's content. (replaces e.g. 'adm\*')

- `endswith`: The value is expected at the end of the field's content (replaces e.g. '\*\\cmd.exe')

- `contains`: Puts `*` wildcards around the values, such that the value is matched anywhere in the
  field.

* `exists`: Defines that a certain field has to exist or must not exist in a log event by providing a boolean value. Note that this check only verifies the presence of a field, not its value, be it empty or null.
* `cased`: Values are applied case sensitively. Default Sigma behavior is case-insensitive matching.
* `neq`: The field is different from the value. It's can be used with string or number.

### String Modifiers<a name="string-modifiers"></a>

The modifiers listed in this section can only be applied to string values.

- `windash`: Creates all possible permutations of the `-`, `/`, `–` (en dash), `—` (em dash), and `―` (horizontal bar) characters. Windows command line flags can often be indicated by both characters. Using the `windash` modifier converts the aforementioned characters interchangeably and uses all possible permutation of strings in the selection.

#### Regular Expression<a name="regular-expression"></a>

- `re`: Value is handled as a regular expression by backends. Regex is matched case-sensitive by default.

  - Currently, the supported flavor is PCRE with the following metacharacters:
    - Wildcards: `.`.
    - Anchors: `^`, `$`.
    - Quantifiers: `*`, `+`, `?`, `{n,m}`.
    - Character Classes: [a-z], [^a-z].
    - Grouping and Capturing: `()`.
    - Alternation: `|`.
  - The following metacharacters are unsupported:
    - Character Classes: `[[:digit:]]`
    - Lookahead Assertions:
      - Positive Lookahead: `(?=...)`
      - Negative Lookahead: `(?!...)`
      - Positive Lookbehind: `(?<=...)`
      - Negative Lookbehind: `(?<!...)`
    - Atomic Grouping: `(?>`

- `re` sub-modifiers:

  - `i`: (insensitive) to enable case-insensitive matching.
  - `m`: (multi line) to match across multiple lines. `^` /`$` match the start/end of line.
  - `s`: (single line) to enable that dot (`.`) matches all characters, including the newline character.

#### Encoding<a name="encoding"></a>

- `base64`: The value is encoded with Base64.

- `base64offset`: If a value might appear somewhere in a base64-encoded string the representation
  might change depending on the position of the value in the overall string. There are three variants for shifts
  by zero to two bytes and except the first and last byte the encoded values have a static part in
  the middle that can be recognized.

- `base64` sub-modifiers:

  - `utf16le`: Transforms value to UTF16-LE encoding, e.g. `cmd` > `63 00 6d 00 64 00`
  - `utf16be`: Transforms value to UTF16-BE encoding, e.g. `cmd` > `00 63 00 6d 00 64`
  - `utf16`: Prepends a [byte order mark](https://en.wikipedia.org/wiki/Byte_order_mark) and encodes UTF16, e.g. `cmd` > `FF FE 63 00 6d 00 64 00`
  - `wide`: an alias for the `utf16le` modifier.

### Numeric Modifiers<a name="numeric-modifiers"></a>

The modifiers listed in this section can only be applied to numeric values.

- `lt`: Field is less than the value
- `lte`: Field is less or equal than the value
- `gt`: Field is greater than the value
- `gte`: Field is greater or equal than the value

### Time Modifiers<a name="time-modifiers"></a>

The modifiers listed in this section can only be applied to date values.
it extracts a numeric value from a date.

**Warning**: It is not designed to handle timezone or format conversions.

- `minute`: number between 0 and 59.
- `hour`: number between 0 and 23.
- `day`: number between 1 and 31.
- `week`: number between 1 and 52.
- `month`: number between 1 and 12.
- `year`: number of the year

### IP (Internet Protocol) Modifiers<a name="ip-internet-protocol-modifiers"></a>

The modifiers listed in this section can only be applied to IP values.

- `cidr`: The value is handled as an CIDR by backends. Supports both IPv4 and IPv6 notations. Example: `DestinationIp|cidr: 10.0.0.0/8`

### Specific Modifiers<a name="specific-modifiers"></a>

- `expand`: Modifier for expansion of placeholders in values. The final behavior of the replacement is determined by processing pipeline transformations. Current possibilities in pySigma are:

  - Expand to value list (`ValueListPlaceholderTransformation`/`value_placeholders`)
  - Replace with query expression in target query language (`QueryExpressionPlaceholderTransformation`/`query_expression_placeholders`)
  - Replace placeholder with wildcard `*`, which should only be used as last resort. (`WildcardPlaceholderTransformation`/`wildcard_placeholders`)

- `fieldref`: Modifies a plain string into a field reference. A field reference can be used to compare fields of matched
  events directly at query/matching time.

## History<a name="history"></a>

- 2025-07-17 Modifiers Appendix v2.1.0
  - `neq` can be use with string or number
- 2025-03-03 Modifiers Appendix v2.1.0
  - Add time modifiers
- 2024-08-10 Modifiers Appendix v2.0.1
  - Add regular expression flavor definition.
  - restructure titles
- 2024-08-08 Modifiers Appendix v2.0.0
- 2023-05-27 Modifiers Appendix v1.0.4
  - Update from PySigma 0.7.6
  - Add `fieldref`
- 2023-05-21 Modifiers Appendix v1.0.3
  - Creation of the file
- 2017 Sigma creation
