# Custom Taxonomy

The following document defines the field names and log sources that use custom taxonomy

- Version 1.0.0
- Release date 2025-07-30

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Warning](#warning)
- [Network Events](#network-events)
  - [Network Connection](#network-connection)
  - [Network DNS](#network-dns)
- [History](#history)

<!-- mdformat-toc end -->

## Warning

You MUST use the `taxonomy` field in the rule otherwise it is considered as `sigma`.

## Network Events

Network events can be defined with the generic logsource category *network*.

The event scope can be further restricted with *service*.

### Network Connection

This logsource covers networks connection in general.

```yml
category: network
service: connection
```

The field names follow the field names used in [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/ecs-network.html) events `taxonomy: ecs`:

| Field Name           | Example Value                  | Comment                                           |
| -------------------- | ------------------------------ | ------------------------------------------------- |
| @timestamp           | 2025-05-08T14:38:35.000Z       | Event timestamp in UTC                            |
| event.duration       | 0.005726                       | Connection duration in seconds                    |
| event.id             | CXWfMc4eWKNBm1O4fl             | Unique connection identifier                      |
| network.type         | ipv4                           | Network layer type (e.g., ipv4, ipv6, ipsec)      |
| network.transport    | tcp                            | Transport layer protocol (e.g., tcp, udp)         |
| network.protocol     | http                           | Application layer protocol (e.g., http, dns, ssh) |
| source.ip            | 192.168.1.100                  | Source IP address                                 |
| source.port          | 54321                          | Source port number                                |
| destination.ip       | 93.184.216.34                  | Destination IP address                            |
| destination.port     | 443                            | Destination port number                           |
| source.packets       | 98                             | Number of packets                                 |
| destination.packets  | 45                             | Number of packets                                 |
| source.bytes         | 2159                           | Number of bytes                                   |
| destination.bytes    | 4739                           | Number of bytes                                   |
| network.community_id | 1:LQU9qZlK+B5F3KDmev6m5PMibrg= | Community ID hash                                 |
| network.state        | SF                             | State of the connection                           |
| network.history      | shADd                          | History of the connection                         |

### Network DNS

This logsource covers DNS queries in general.

```yml
category: network
service: dns
```

The field names follow the field names used in [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/ecs-dns.html) events `taxonomy: ecs`:

| Field Name           | Example Value                  | Comment                      |
| -------------------- | ------------------------------ | ---------------------------- |
| @timestamp           | 2025-05-08T14:38:35.000Z       | Event timestamp in UTC       |
| event.id             | CXWfMc4eWKNBm1O4fl             | Unique connection identifier |
| source.ip            | 192.168.1.100                  | Source IP address            |
| source.port          | 54321                          | Source port number           |
| destination.ip       | 93.184.216.34                  | Destination IP address       |
| destination.port     | 443                            | Destination port number      |
| network.community_id | 1:LQU9qZlK+B5F3KDmev6m5PMibrg= | Community ID hash            |
| dns.id               | CXWfMc4eWKNBm1O4fl             | DNS transaction identifier   |
| dns.question.name    | example.com                    | DNS question name            |
| dns.question.type    | A                              | DNS question type            |
| dns.question.class   | IN                             | DNS question class           |
| dns.answers.name     | example.com                    | DNS answer name              |
| dns.answers.type     | A                              | DNS answer type              |
| dns.answers.class    | IN                             | DNS answer class             |
| dns.answers.data     | 93.184.216.34                  | DNS answer data              |
| dns.answers.ttl      | 3600                           | DNS answer TTL               |
| dns.header.flags     | RD, RA                         | DNS header flags             |
| dns.response.code    | NOERROR                        | DNS response code            |

## History

- 2025-07-30 Custom Taxonomy v1.0.0
  - Initial release
  - Network Events
