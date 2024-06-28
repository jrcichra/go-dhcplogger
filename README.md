# go-dhcplogger

[![Build Status](https://drone.srv.kojedz.in/api/badges/krichy/go-dhcplogger/status.svg)](https://drone.srv.kojedz.in/krichy/go-dhcplogger)

Package for capturing and logging all sent DHCPACK packets on an interface. May be useful for auditing purposes.

## Preparations

Packets are sent to a PostgreSQL database, the table may be prepared with the following statement:

```sql
CREATE TABLE dhcp_packets (
    id        bigserial primary key,
    ts        timestamptz not null,
    client    macaddr not null,
    agent     varchar(256),
    ip        inet not null,
    leasetime integer,
    packet    text
);
```

## Invocation

The program may be run as:

```shell
# ./go-dhcplogger -interface=eth0
```

For all switches and defaults, see

```shell
# ./go-dhcplogger -h
```

## Operation

The program starts listening for dhcp packets on the specified interface. Each packet is parsed and stored in SQL. 4 goroutines are used for this. If for some reason the sql is unavailable, up to `-max-queue-length` packets will be queued. All packets are retried `-retries` times with 1 second delays, then dropped.
