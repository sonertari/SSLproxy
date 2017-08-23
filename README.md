# SSLproxy - transparent SSL/TLS proxy for diverting packets to other programs

Copyright (C) 2017, [Soner Tari](https://github.com/sonertari).  
https://github.com/sonertari/SSLproxy

Copyright (C) 2009-2016, [Daniel Roethlisberger](//daniel.roe.ch/).  
http://www.roe.ch/SSLsplit

## Overview

SSLproxy is a proxy for SSL/TLS encrypted network connections.  It is intended 
to be used for diverting network traffic to other programs, such as UTM 
services.

SSLproxy is designed to transparently terminate connections that are redirected 
to it using a network address translation engine.  SSLproxy then terminates 
SSL/TLS and initiates a new SSL/TLS connection to the original destination 
address. Packets received on the client side are decrypted and sent to the 
program listening on a port given in the proxy specification. SSLproxy inserts 
in the first packet the address and port it is expecting to receive the packets 
back from the program. Upon receiving the packets back, SSLproxy re-encrypts 
and sends them to their original destination. The return traffic follows the 
same path back to the client.

This is similar in principle to [divert 
sockets](https://man.openbsd.org/divert.4), where the packet filter diverts the 
packets to a program listening on a divert socket, and after processing the 
packets the program reinjects them into the kernel. If there is no program 
listening on that divert socket or the program does not reinject the packets to 
the kernel, the connection is effectively blocked. In the case of SSLproxy, 
SSLproxy acts as both the packet filter and the kernel, and the communication 
occurs over networking sockets.

For example, given the following proxy specification:

	https 127.0.0.1 8443 up:8080

The SSLproxy listens for HTTPS connections on 127.0.0.1:8443. Upon receiving a 
connection from the Client, it decrypts and diverts the packets to a Program 
listening on 127.0.0.1:8080. After processing the packets, the Program gives 
them back to the SSLproxy listening on a dynamically assigned address, which 
the Program obtains from the first packet in the connection. Then the SSLproxy 
re-encrypts and sends the packets to the Server. The response from the Server 
follows the same path to the Client in reverse order.

	            Program
	              ^^
	             /  \
	            v    v
	Client <-> SSLproxy <-> Server   

The program that packets are diverted to should support this mode of operation.
Specifically, it should be able to recognize the SSLproxy address in the first
packet, and give the first and subsequent packets back to the SSLproxy 
listening on that address, instead of sending them to the original destination 
as it normally would.

SSLproxy supports plain TCP, plain SSL, HTTP, HTTPS, POP3, POP3S, SMTP, and 
SMTPS connections over both IPv4 and IPv6.  SSLproxy fully supports Server Name 
Indication (SNI) and is able to work with RSA, DSA and ECDSA keys and DHE and 
ECDHE cipher suites.  Depending on the version of OpenSSL, SSLproxy supports 
SSL 3.0, TLS 1.0, TLS 1.1 and TLS 1.2, and optionally SSL 2.0 as well.

For SSL/TLS connections, SSLproxy generates and signs forged X509v3 
certificates on-the-fly, mimicking the original server certificate's subject 
DN, subjectAltName extension and other characteristics.  SSLproxy has the 
ability to use existing certificates of which the private key is available, 
instead of generating forged ones.  SSLproxy supports NULL-prefix CN 
certificates but otherwise does not implement exploits against specific 
certificate verification vulnerabilities in SSL/TLS stacks.

SSLproxy implements a number of defences against mechanisms which would 
normally prevent MitM attacks or make them more difficult.  SSLproxy can deny 
OCSP requests in a generic way.  For HTTP and HTTPS connections, SSLproxy 
removes response headers for HPKP in order to prevent server-instructed public 
key pinning, for HSTS to avoid the strict transport security restrictions, and 
Alternate Protocols to prevent switching to QUIC/SPDY.  HTTP compression, 
encodings and keep-alive are disabled to make the logs more readable.

Another reason to disable persistent connections is to reduce file descriptor 
usage. Accordingly, connections are closed if they remain idle for a certain 
period of time. The default timeout is 120 seconds, which can be changed in a 
configuration file.

In order to maximize the chances that a connection can be successfully split, 
SSLproxy does not verify upstream server certificates.  Instead, all 
certificates including self-signed are accepted and if the expected hostname 
signalled in SNI is missing from the server certificate, it will be added to 
dynamically forged certificates.

SSLproxy does not automagically redirect any network traffic.  To actually
implement a proxy, you also need to redirect the traffic to the system
running \fBsslproxy\fP.  Your options include running \fBsslproxy\fP on a
legitimate router, ARP spoofing, ND spoofing, DNS poisoning, deploying a rogue
access point (e.g. using hostap mode), physical recabling, malicious VLAN
reconfiguration or route injection, /etc/hosts modification and so on.

As SSLproxy is based on SSLsplit, this is a modified SSLsplit README file.
See the manual page sslproxy(1) for details on using SSLproxy and setting up
the various NAT engines.


## Requirements

SSLproxy depends on the OpenSSL and libevent 2.x libraries.
The build depends on GNU make and a POSIX.2 environment in `PATH`.
If available, pkg-config is used to locate and configure the dependencies.
The optional unit tests depend on the check library.

SSLproxy currently supports the following operating systems and NAT mechanisms:

-   FreeBSD: pf rdr and divert-to, ipfw fwd, ipfilter rdr
-   OpenBSD: pf rdr-to and divert-to
-   Linux: netfilter REDIRECT and TPROXY
-   Mac OS X: pf rdr and ipfw fwd

Support for local process information (`-i`) is currently available on Mac OS X
and FreeBSD.

SSL/TLS features and compatibility greatly depend on the version of OpenSSL
linked against; for optimal results, use a recent release of OpenSSL proper.
OpenSSL forks like BoringSSL may or may not work.


## Installation

With OpenSSL, libevent 2.x, pkg-config and check available, run:

    make
    make test       # optional unit tests
    make install    # optional install

Dependencies are autoconfigured using pkg-config.  If dependencies are not
picked up and fixing `PKG_CONFIG_PATH` does not help, you can specify their
respective locations manually by setting `OPENSSL_BASE`, `LIBEVENT_BASE` and/or
`CHECK_BASE` to the respective prefixes.

You can override the default install prefix (`/usr/local`) by setting `PREFIX`.
For more build options see `GNUmakefile`.


## Documentation

See `NEWS.md` for release notes listing significant changes between releases.
See `HACKING.md` for information on development and how to submit bug reports.
See `AUTHORS.md` for the list of contributors.


## License

SSLsplit is provided under a 2-clause BSD license.
SSLsplit contains components licensed under the MIT and APSL licenses.
See `LICENSE.md` and the respective source file headers for details.
The modifications for SSLproxy are licensed under the same terms as SSLsplit.

