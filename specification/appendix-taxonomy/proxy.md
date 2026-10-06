# category: proxy

```yaml
logsource:
    category: proxy
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

The log file written by the proxy. The rules match on fields, not on keywords.

## Points of Attention

- Only the fields that the log format configuration of the proxy declares are written to the log, so a field of the list below can be missing from the events of a given product.
- The field names come from the log formats of the common proxies, not from the [W3C extended log file format](https://www.w3.org/TR/WD-logfile.html). That draft defines the `c-`, `s-`, `r-`, `cs-` and `sc-` prefixes and a `prefix(header)` notation for the HTTP header fields, `sc(Referer)` for the referring site for example. `c-useragent`, `c-uri-extension`, `src_ip` and `dst_ip` are specific to the proxies that write them.

## Fields

| Field Name        | Example Value        | Comment                                                                                                               |
| ----------------- | -------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `c-uri`           | /download/setup.exe  | URL requested by the client                                                                                           |
| `c-uri-extension` | exe                  | Extension of the URL. Commonly is the requested extension of a file name                                              |
| `c-uri-query`     | id=42                | Path component of requested URL                                                                                       |
| `c-uri-stem`      | /download/setup      | Stem of the requested URL                                                                                             |
| `c-useragent`     | Mozilla/5.0          | The client's user agent                                                                                               |
| `cs-bytes`        | 1234                 | Number of bytes sent from the server                                                                                  |
| `cs-cookie`       | session=1a2b3c       | Cookie headers sent from client to server                                                                             |
| `cs-host`         | www.example.com      | Host header sent from client to server                                                                                |
| `cs-method`       | GET                  | HTTP request method                                                                                                   |
| `cs-version`      | HTTP/1.1             | The HTTP protocol version that the client used                                                                        |
| `dst_ip`          | 172.30.255.255       | The IP address of the server                                                                                          |
| `r-dns`           | www.example.com      | The domain requested, additionally referred to as the Host header or URL domain. Recommends `cs-host` over this field |
| `sc(Referer)`     | https://example.com/ | The referring link or site                                                                                            |
| `sc-bytes`        | 4321                 | Number of bytes sent from the client                                                                                  |
| `sc-status`       | 200                  | The HTTP status code                                                                                                  |
| `src_ip`          | 172.22.255.255       | The IP address of the client that made the request                                                                    |
