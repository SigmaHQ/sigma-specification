# category: webserver

```yaml
logsource:
    category: webserver
```

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Telemetry](#telemetry)
- [Points of Attention](#points-of-attention)
- [Fields](#fields)

<!-- mdformat-toc end -->

## Telemetry

The access log written by the web server. The rules match on fields, not on keywords.

## Points of Attention

- The field names are the ones the Microsoft HTTP Server API writes, see the [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging). The other web servers that write the [W3C extended log file format](https://www.w3.org/TR/WD-logfile.html) name the header fields with the `prefix(header)` notation of that draft, `cs(Referer)` for the referring site for example, instead of the name of the field alone.
- Two rules of the rules repository match on `cs-referer` and `cs-user-agent`, which the Microsoft HTTP Server API doesn't write.

## Fields

| Field Name        | Example Value        | Comment                                                                                                                                 |
| ----------------- | -------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `c-ip`            | 172.22.255.255       | The IP address of the client that accessed the server                                                                                   |
| `cs-bytes`        | 1234                 | The number of bytes received by the server                                                                                              |
| `cs(Cookie)`      | session=1a2b3c       | The content of the cookie sent or received, if any                                                                                      |
| `cs-host`         | www.example.com      | The content of the host header                                                                                                          |
| `cs-method`       | GET                  | The action the client was trying to perform, for example a GET method                                                                   |
| `cs(Referrer)`    | https://example.com/ | The previous site visited by the user, which provided a link to the current site                                                        |
| `cs-uri-query`    | id=42                | The query, if any, the client was trying to perform                                                                                     |
| `cs-uri-stem`     | /default.htm         | The resource accessed, for example Default.htm                                                                                          |
| `cs-username`     | -                    | The name of the authenticated user that accessed the server. This does not include anonymous users, who are represented by a hyphen (-) |
| `cs(User-Agent)`  | Mozilla/5.0          | The browser used on the client                                                                                                          |
| `cs-version`      | HTTP/1.1             | The protocol (HTTP, FTP) version used by the client                                                                                     |
| `date`            | 2002-05-02           | The date that the activity occurred                                                                                                     |
| `s-computername`  | W3SVC1               | The name of the server on which the log entry was generated                                                                             |
| `s-ip`            | 172.30.255.255       | The IP address of the server on which the log entry was generated                                                                       |
| `s-port`          | 80                   | The port number the client is connected to                                                                                              |
| `s-sitename`      | W3SVC1               | The Internet service and instance number that was accessed by a client                                                                  |
| `sc-bytes`        | 4321                 | The number of bytes sent by the server                                                                                                  |
| `sc-status`       | 200                  | The status of the action, in HTTP or FTP terms                                                                                          |
| `sc-substatus`    | 0                    | The substatus error code                                                                                                                |
| `sc-win32-status` | 0                    | The status of the action, in terms used by Microsoft Windows                                                                            |
| `streamid`        | 8000                 | The stream identifier                                                                                                                   |
| `time`            | 17:42:15             | The time that the activity occurred                                                                                                     |
| `time-taken`      | 15                   | The duration of the action, in milliseconds                                                                                             |
