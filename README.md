# SSLproxy - transparent SSL/TLS proxy for decrypting and diverting network traffic to other programs for deep SSL inspection [![Build Status](https://travis-ci.org/sonertari/SSLproxy.svg?branch=master)](https://travis-ci.org/sonertari/SSLproxy)

Copyright (C) 2017-2021, [Soner Tari](mailto:sonertari@gmail.com).
https://github.com/sonertari/SSLproxy

Copyright (C) 2009-2019, [Daniel Roethlisberger](//daniel.roe.ch/).
https://www.roe.ch/SSLsplit

## Overview

SSLproxy is a proxy for SSL/TLS encrypted network connections. It is intended 
to be used for decrypting and diverting network traffic to other programs, such 
as UTM services, for deep SSL inspection.

[The UTMFW project](https://github.com/sonertari/UTMFW) uses SSLproxy to 
decyrpt and feed network traffic into its UTM services: Web Filter, POP3 
Proxy, SMTP Proxy, and Inline IPS; and also indirectly into Virus Scanner and 
Spam Filter through those UTM software. Given that most of the Internet 
traffic is encrypted now, it wouldn't be possible without SSLproxy to deeply 
inspect most of the network traffic passing through UTMFW.

See [this presentation](https://drive.google.com/open?id=12YaGIGs0-xfpqMNAY3rzUbIyed-Tso8W) 
for a summary of SSL interception and potential issues with middleboxes that 
support it.

### Mode of operation

SSLproxy is designed to transparently terminate connections that are redirected
to it using a network address translation engine. SSLproxy then terminates
SSL/TLS and initiates a new SSL/TLS connection to the original destination
address. Packets received on the client side are decrypted and sent to the
program listening on a port given in the proxy specification. SSLproxy inserts
in the first packet the address and port it is expecting to receive the packets
back from the program. Upon receiving the packets back, SSLproxy re-encrypts
and sends them to their original destination. The return traffic follows the
same path back to the client in reverse order.

![Mode of Operation Diagram](https://drive.google.com/uc?id=1N_Yy5nMPDSvY8YaNFd4sHvipyLWq5zDy)

This is similar in principle to [divert 
sockets](https://man.openbsd.org/divert.4), where the packet filter diverts the 
packets to a program listening on a divert socket, and after processing the 
packets the program reinjects them into the kernel. If there is no program 
listening on that divert socket or the program does not reinject the packets 
into the kernel, the connection is effectively blocked. In the case of 
SSLproxy, SSLproxy acts as both the packet filter and the kernel, and the 
communication occurs over networking sockets.

SSLproxy does not automagically redirect any network traffic.  To actually
implement a proxy, you also need to redirect the traffic to the system running 
sslproxy.  Your options include running sslproxy on a legitimate router, ARP 
spoofing, ND spoofing, DNS poisoning, deploying a rogue access point (e.g. 
using hostap mode), physical recabling, malicious VLAN reconfiguration or 
route injection, /etc/hosts modification and so on.

#### Proxy specification

For example, given the following proxy specification:

	https 127.0.0.1 8443 up:8080

- SSLproxy listens for HTTPS connections on 127.0.0.1:8443.
- Upon receiving a connection from the Client, it decrypts and diverts the 
packets to a Program listening on 127.0.0.1:8080. The default divert address 
is 127.0.0.1, which can be configured by the `ua` option.
- After processing the packets, the Program gives them back to SSLproxy 
listening on a dynamically assigned address, which the Program obtains from 
the SSLproxy line in the first packet in the connection.
- Then SSLproxy re-encrypts and sends the packets to the Server.

The response from the Server follows the same path back to the Client in 
reverse order.

#### SSLproxy line

A sample line SSLproxy inserts into the first packet in the connection is the 
following:

	SSLproxy: [127.0.0.1]:34649,[192.168.3.24]:47286,[192.168.111.130]:443,s

- The first IP:port pair is a dynamically assigned address that SSLproxy 
expects the program send the packets back to it.
- The second and third IP:port pairs are the actual source and destination 
addresses of the connection respectively. Since the program receives the 
packets from SSLproxy, it cannot determine the source and destination 
addresses of the packets by itself, e.g by asking the NAT engine, hence must 
rely on the information in the SSLproxy line.
- The last letter is either s or p, for SSL/TLS encrypted or plain traffic 
respectively. This information is also important for the program, because it 
cannot reliably determine if the actual network traffic it is processing was 
encrypted or not before being diverted to it.

#### Listening program

The program that packets are diverted to should support this mode of operation.
Specifically, it should be able to recognize the SSLproxy address in the first
packet, and give the first and subsequent packets back to SSLproxy listening 
on that address, instead of sending them to the original destination as it 
normally would.

You can use any software as a listening program as long as it supports this 
mode of operation. So existing or new software developed in any programming 
language can be modified to be used with SSLproxy to inspect and/or modify any 
or all parts of the packets diverted to it.

You can offload the system SSLproxy is running on by diverting packets to 
remote listening programs too. For example, given the following proxy 
specification:

	https 127.0.0.1 8443 up:8080 ua:192.168.0.1 ra:192.168.1.1

- The `ua` option instructs SSLproxy to divert packets to 192.168.0.1:8080, 
instead of 127.0.0.1:8080 as in the previous proxyspec example.
- The `ra` option instructs SSLproxy to listen for returned packets from the 
program on 192.168.1.1, instead of 127.0.0.1 as in the previous SSLproxy line.

Accordingly, the SSLproxy line now becomes:

	SSLproxy: [192.168.1.1]:34649,[192.168.3.24]:47286,[192.168.111.130]:443,s

So, the listening program can be running on a machine anywhere in the world. 
Since the packets between SSLproxy and the listening program are always 
unencrypted, you should be careful while using such a setup.

### Protocols

#### Supported protocols

SSLproxy supports plain TCP, plain SSL, HTTP, HTTPS, POP3, POP3S, SMTP, and 
SMTPS connections over both IPv4 and IPv6. It also has the ability to 
dynamically upgrade plain TCP to SSL in order to generically support SMTP 
STARTTLS and similar upgrade mechanisms. Depending on the version of OpenSSL, 
SSLproxy supports SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, and TLS 1.3, and 
optionally SSL 2.0 as well. SSLproxy supports Server Name Indication (SNI), 
but not Encrypted SNI in TLS 1.3. It is able to work with RSA, DSA and ECDSA 
keys and DHE and ECDHE cipher suites.

The following features of SSLproxy are IPv4 only:
- Divert addresses for listening programs in proxyspecs
- SSLproxy return addresses dynamically assigned to connections
- IP addresses in the ua and ra options
- IP and ethernet addresses of clients in user authentication
- Target IP and ethernet addresses in mirror logging

#### OCSP, HPKP, HSTS, Upgrade et al.

SSLproxy implements a number of defences against mechanisms which would
normally prevent MitM attacks or make them more difficult. SSLproxy can deny
OCSP requests in a generic way. For HTTP and HTTPS connections, SSLproxy
mangles headers to prevent server-instructed public key pinning (HPKP), avoid
strict transport security restrictions (HSTS), avoid Certificate Transparency
enforcement (Expect-CT) and prevent switching to QUIC/SPDY, HTTP/2 or
WebSockets (Upgrade, Alternate Protocols). HTTP compression, encodings and
keep-alive are disabled to make the logs more readable.

Another reason to disable persistent connections is to reduce file descriptor 
usage. Accordingly, connections are closed if they remain idle for a certain 
period of time. The default timeout is 120 seconds, which can be configured by 
the ConnIdleTimeout option.

#### Protocol validation

Protocol validation makes sure the traffic handled by a proxyspec is using the 
protocol specified in that proxyspec. The ValidateProto option can be used to 
enable global and/or per-proxyspec protocol validation. This feature currently 
supports HTTP, POP3, and SMTP protocols. If a connection cannot pass protocol 
validation, then it is terminated.

SSLproxy uses only client requests for protocol validation. However, it also 
validates SMTP responses until it starts processing the packets from the 
client. If there is no excessive fragmentation, the first couple of packets in 
the connection should be enough for validating protocols.

### Certificates

#### Certificate forging

For SSL and HTTPS connections, SSLproxy generates and signs forged X509v3
certificates on-the-fly, mimicking the original server certificate's subject
DN, subjectAltName extension and other characteristics. SSLproxy has the
ability to use existing certificates of which the private key is available,
instead of generating forged ones. SSLproxy supports NULL-prefix CN
certificates but otherwise does not implement exploits against specific
certificate verification vulnerabilities in SSL/TLS stacks.

#### Certificate verification

SSLproxy verifies upstream certificates by default. If the verification fails,
the connection is terminated immediately. This is in contrast to SSLsplit,
because in order to maximize the chances that a connection can be successfully
split, SSLsplit accepts all certificates by default, including self-signed
ones. See [The Risks of SSL Inspection](https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html)
for the reasons of this difference. You can disable this feature by the 
VerifyPeer option.

#### Client certificates

SSLproxy uses the certificate and key from the pemfiles configured by the 
ClientCert and ClientKey options when the destination requests client 
certificates. These options can be defined globally and/or per-proxyspec.

Alternatively, you can use the PassSite option to pass through certain 
destinations requesting client certificates.

### User authentication

If the UserAuth option is enabled, SSLproxy requires network users to log in 
to the system to establish connections to the external network.

SSLproxy determines the user owner of a connection using a `users` table in an 
SQLite3 database configured by the UserDBPath option. The users table should 
be created using the following SQL statement:

	CREATE TABLE USERS(
	   IP             CHAR(45)     PRIMARY KEY     NOT NULL,
	   USER           CHAR(31)     NOT NULL,
	   ETHER          CHAR(17)     NOT NULL,
	   ATIME          INT          NOT NULL,
	   DESC           CHAR(50)
	);

SSLproxy does not create this users table or the database file by itself, nor 
does it log users in or out. So the database file and the users table should 
already exist at the location pointed to by the UserDBPath option. An external 
program should log users in and out on the users table. The external program 
should fill out all the fields in user records, except perhaps for the DESC 
field, which can be left blank.

When SSLproxy accepts a connection, it obtains the ethernet address of the
client IP address from the arp cache of the system, then compares it with
the value in the users table. If the ethernet addresses do not match, the 
connection is redirected to a login page configured by the UserAuthURL option.

SSLproxy also compares the atime value in the users table with the current 
system time. If the difference is greater than the value configured by the 
UserTimeout option, then the connection is redirected to the login page.

The atime of the IP address in the users table is updated with the system time 
while the connection is being terminated. Since this atime update is executed 
using a privsep command, it is expensive. So, to reduce the frequency of such 
updates, it is deferred until after the user idle time is more than half of 
the timeout period.

If a description text is provided in the DESC field, it can be used with the 
PassSite option to treat the user logged in from different locations, i.e. 
from different client IP addresses, separately.

If the UserAuth option is enabled, the user owner of the connection is 
appended at the end of the SSLproxy line, so that the listening program can 
parse and use this information in its logic and/or logging:

	SSLproxy: [127.0.0.1]:34649,[192.168.3.24]:47286,[192.168.111.130]:443,s,soner

The user authentication feature is currently available on OpenBSD and Linux only.

#### User control lists

DivertUsers and PassUsers options can be used to divert, pass through, or 
block users.

- If neither DivertUsers nor PassUsers is defined, all users are diverted to 
listening programs.
- Connections from users in DivertUsers, if defined, are diverted to listening 
programs.
- Connections from users in PassUsers, if defined, are simply passed through 
to their original destinations. SSLproxy engages the Passthrough mode for that 
purpose.
- If both DivertUsers and PassUsers are defined, users not listed in either of 
the lists are blocked. SSLproxy simply terminates their connections.
- If *no* DivertUsers list is defined, only users *not* listed in PassUsers 
are diverted to listening programs.

These user control lists can be defined globally or per-proxyspec.

### Excluding sites from SSL inspection

PassSite option allows certain SSL sites to be excluded from SSL inspection. 
If a PassSite matches the SNI or common names in the SSL certificate of a 
connection, that connection is passed through the proxy without being diverted 
to the listening program. SSLproxy engages the Passthrough mode for that 
purpose. For example, sites requiring client authentication can be added as 
PassSite.

Per-site filters can be defined using client IP addresses, users, and 
description keywords. If the UserAuth option is disabled, only client IP 
addresses can be used in PassSite filters. Multiple sites can be defined, one 
on each line.

### Logging

Logging options include traditional SSLproxy connect and content log files as
well as PCAP files and mirroring decrypted traffic to a network interface.
Additionally, certificates, master secrets and local process information can be
logged.

See the manual pages sslproxy(1) and sslproxy.conf(5) for details on using 
SSLproxy, setting up the various NAT engines, and for examples.


## Requirements

SSLproxy depends on the OpenSSL, libevent 2.x, libpcap, libnet 1.1.x, and 
sqlite3 libraries by default. Libpcap and libnet are not needed if the 
mirroring feature is omitted. Sqlite3 is not needed if the user authentication 
feature is omitted. The build depends on GNU make and a POSIX.2 environment 
in `PATH`. If available, pkg-config is used to locate and configure the 
dependencies. The optional unit tests depend on the check library. The 
optional end-to-end tests depend on the [TestProxy](https://github.com/sonertari/TestProxy) 
tool, and are supported only on Linux.

SSLproxy currently supports the following operating systems and NAT mechanisms:

- FreeBSD: pf rdr and divert-to, ipfw fwd, ipfilter rdr
- OpenBSD: pf rdr-to and divert-to
- Linux: netfilter REDIRECT and TPROXY
- Mac OS X: pf rdr and ipfw fwd

Support for local process information (`-i`) is currently available on Mac OS X
and FreeBSD.

SSL/TLS features and compatibility greatly depend on the version of OpenSSL
linked against. For optimal results, use a recent release of OpenSSL or
LibreSSL.


## Installation

With the requirements above available, run:

    make
    make test       # optional unit and e2e tests
    make sudotest   # optional unit tests requiring privileges
    make install    # optional install

Dependencies are autoconfigured using pkg-config. If dependencies are not
picked up and fixing `PKG_CONFIG_PATH` does not help, you can specify their
respective locations manually by setting `OPENSSL_BASE`, `LIBEVENT_BASE`,
`LIBPCAP_BASE`, `LIBNET_BASE`, `SQLITE_BASE` and/or `CHECK_BASE` to the 
respective prefixes.

You can override the default install prefix (`/usr/local`) by setting `PREFIX`.
For more build options and build-time defaults see [`GNUmakefile`](GNUmakefile)
and [`defaults.h`](defaults.h).


## Documentation

See the manual pages `sslproxy(1)` and `sslproxy.conf(5)` for user
documentation. See [`NEWS.md`](NEWS.md) for release notes listing significant
changes between releases and [`SECURITY.md`](SECURITY.md) for information on
security vulnerability disclosure.


## License

SSLproxy is provided under a 2-clause BSD license.
SSLproxy contains components licensed under the MIT and APSL licenses.
See [`LICENSE`](LICENSE), [`LICENSE.contrib`](LICENSE.contrib) and
[`LICENSE.third`](LICENSE.third) as well as the respective source file headers
for details.


## Credits

See [`AUTHORS.md`](AUTHORS.md) for the list of contributors.

SSLproxy was inspired by and has been developed based on [SSLsplit](https://www.roe.ch/SSLsplit) 
by Daniel Roethlisberger.
