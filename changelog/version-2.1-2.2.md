# Changes and Feature Introduced in V2.2.0

The following is a non-exhaustive list of changes between the v2.1.0 and v2.2.0 specification.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Generality](#generality)
- [Modifiers](#modifiers)
- [Tags](#tags)
- [Taxonomy](#taxonomy)
- [Correlation](#correlation)
- [Filter](#filter)
- [Rules](#rules)

<!-- mdformat-toc end -->

## Generality

## Modifiers

- `re` : Provides a more detailed definition and descripions
- `fieldref` : Rejects wildcards in the referenced field name, may be followed by `contains`, `startswith`, or `endswith`, and combines with `neq`
- `neq` : Removed the duplicate entry from the numeric modifiers, since `neq` is the generic negation modifier

## Tags

## Taxonomy

- Split the taxonomy appendix into one page per log source, in `specification/appendix-taxonomy/`. The appendix keeps the list of the pages, grouped by the folder of the rules repository that uses them.
- `category: webserver` is documented with the field names of the Microsoft HTTP Server API: `cs(Referrer)`, `cs(User-Agent)`, `cs(Cookie)`, `sc-win32-status`, `sc-substatus` and `streamid`. It replaces `cs-referer`, `cs-user-agent`, `cs-cookie` and `c-win32-status`.
- `category: proxy` doesn't claim the W3C extended log file format anymore: `cs-referrer` is replaced by `sc(Referer)`, `c-useragent` is kept as the field name of the proxies that write it.
- Document the fields the event sources write in the `## Fields` section of the Windows pages: one subsection per event identifier used by the rules, holding its payload field names, from the manifests and the provider CSVs of [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources). Event identifiers the resource doesn't document are left out.
- Add the log sources that the rules of the repository use and that the appendix didn't document:
  - `product: linux` without a `category` or a `service` attribute
  - `product: windows` without a `category` or a `service` attribute
  - `category: application, product: jvm`
  - `category: application, product: kubernetes, service: audit`
  - `category: application, product: nodejs`
  - `category: application, product: opencanary`
  - `category: application, product: velocity`
  - `product: kubernetes, service: audit`
  - `product: fortigate, service: event`
  - `product: gcp, service: google_workspace.login`
  - `product: huawei, service: bgp`
  - `product: juniper, service: bgp`
  - `product: windows, service: microsoft-servicebus-client`, the temporary name the rules give to `service: servicebus-client` until their validators support it
  - `product: windows, service: smbserver-connectivity`
  - `service: nginx`

## Correlation

- Add `tags` field

## Filter

- Filters can now reference all available rules by using the `filter.rules: any` declaration [PR #430](https://github.com/SigmaHQ/pySigma/pull/430)

## Rules

- `Lists` and `Maps` : add scalar value
