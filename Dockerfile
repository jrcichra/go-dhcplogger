FROM golang:alpine3.12 AS build

RUN apk --no-cache add gcc libc-dev libpcap-dev

ADD . /go/src/github.com/rkojedzinszky/go-dhcplogger

RUN cd /go/src/github.com/rkojedzinszky/go-dhcplogger && go build . && \
    strip -s go-dhcplogger

FROM alpine:3.12

COPY --from=build /go/src/github.com/rkojedzinszky/go-dhcplogger/go-dhcplogger /

RUN apk --no-cache add libpcap libcap && \
    setcap cap_net_raw+ep /go-dhcplogger && \
    apk del libcap

USER 65534

CMD ["/go-dhcplogger", "-interface=eth0"]
