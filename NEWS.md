

### SSLproxy 0.9.9 2025-11-09

-   Fix fd leak, do not setup dst again in autossl, issue #88 reported by 
	@victorjulien
-   Fix memory leak in config load, reported by valgrind
-   Disable r/w cbs and clear all cbs before all bufferevent_free() calls
	Also, disable the events first, then clear the callbacks, for conventional 
	pattern
-   Check fd usage before content logging, issue #88 reported by @victorjulien
	This change is expected to prevent sslproxy to crash if it runs out of fds 
	while content logging
-   Make sure the other conn end not closed before using it
-   Increase sizes of bufs used in ClientHello parsing as a defensive measure 
	against modern TLS handshake sizes, suggested by @dpward
-   Use unused retvals from functions in autossl
-   Remove unused return value
-   Fix recursive expansion in main.mk, thanks to @dpward
-   Improve error handling and memory leak prevention in filter.c, for 
	correctness, suggested and mostly implemented by Copilot
-   Simplify platform check in main.mk for UserAuth feature
-   Print version after unit tests in GitHub Actions


### SSLproxy 0.9.8 2025-05-05

-   Force SSL/TLS configuration in SSL proxyspecs
	SSL proxyspecs should always have a complete SSL/TLS configuration, even
	if their filter rules have complete SSL/TLS configuration, because it is
	very difficult, if not impossible, to check the coverage of filter rules
	to make sure we have complete SSL/TLS configuration if no filter rule
	matches, in which case sslproxy may crash
-   Fix crash if no global ca crt/key specified, issue #80 reported by
	@pranavbhalerao
-   Fix ClientHello parser for TLS 1.3, issue #84 reported by @GhostNaix
-   Fix unit tests on arm64 macOS, issue #81 reported by @jmayer
-   Suppress deprecation warnings for engines in unit tests with OpenSSL 3.x


### SSLproxy 0.9.7 2024-10-15

-   Fix deprecation warnings with OpenSSL 3.x for
	- DH_free()
	- DH config
	- ECDH config
	- RSA functions
	- Engines
-   Remove unused ssl_dh_refcount_inc()
-   Fix memleak, develop proto_free functions for pop3 and smtp, fixes issue
    #72 reported by @applehxb
-   Fix possible memleak and use after free for srchost_clean
-   Use strdup instead of strlen+malloc+memcpy in sys_sockaddr_str(), thanks to
    @disaykin
-   Use CLOCK_REALTIME to fix pcap timestamp, issue #78 thanks to @mdulaney


### SSLproxy 0.9.6 2024-07-04

-   Fix clang-static-analysis warnings, thanks to @disaykin.
-   Use clock_gettime() instead of gettimeofday(), thanks to @disaykin.
-   Fix deprecation warnings for function declarations without a prototype.


### SSLproxy 0.9.5 2024-02-18

-   Fix possible double free of host and serv variables, thanks to @disaykin.
-   Fix possible integer overflow, thanks to @disaykin.
-   Close fds only once, thanks to @disaykin.
-   Fix memory leak, thanks to @disaykin.
-   Handle ftell error, thanks to @disaykin.
-   Fix mismatched call arguments, thanks to @disaykin.
-   Fix memory leak in case of cert key mismatch, thanks to @disaykin.
-   Fix file descriptor leak, thanks to @disaykin.
-   Handle partial write, thanks to @disaykin.
-   Handle return value of gmtime(), thanks to @disaykin.
-   Fix double free bugs, thanks to @disaykin.
	- Bugs found by Svace static analyzer.
-   Fix possible segfault in proto smtp in split mode.
-   Fix retval of privsep_server_opensock_verify(), thanks to @Qbog.
-   Fix header-size calculation in IPv6 packet mirroring, thanks to @matoro.
-   Fix e2e tests with openssl 3.
-   Replace deprecated fail_unless() with ck_assert_msg() in unit tests.


### SSLproxy 0.9.4 2022-12-26

-   Fix byte order for ports in mirror trafic, thanks to piolug93.
-   Fix unit tests with opaque x509 struct.
-   Update testproxy version to 0.0.5.
-   Fix warning for array subscript outside array bounds in function
    declaration.


### SSLproxy 0.9.3 2022-05-02

-   Implement a generic upgrade mechanism with autossl, without STARTTLS.
-   Refactor and improve autossl and split mode.
-   Fix watermarking for underlying buffers in autossl.
-   Fix macOS header selection, update XNU headers for macOS, and re-enable osx
    on Travis CI.
-   Fix the natengine option passed in proxyspecs on command line.
-   Fix enabling of pcap and mirror logging.
-   Fix build errors with OpenSSL 3.x.


### SSLproxy 0.9.2 2021-11-14

-   Update with the license change of the Aho Corasick library to the LGPL.
-   Migrate to travis-ci.com.
-   Various fixes and improvements.


### SSLproxy 0.9.1 2021-11-07

-   Add structured filtering rules:

	    FilterRule {
	        Action (Divert|Split|Pass|Block|Match)

	        # From
	        User (username[*]|$macro|*)  # inline
	        Desc (desc[*]|$macro|*)      # comments
	        SrcIp (clientip[*]|$macro|*) # allowed

	        # To
	        SNI (servername[*]|$macro|*)
	        CN (commonname[*]|$macro|*)
	        Host (host[*]|$macro|*)
	        URI (uri[*]|$macro|*)
	        DstIp (serverip[*]|$macro|*)
	        DstPort (serverport[*]|$macro|*)

	        # Multiple Log lines allowed
	        Log ([[!]connect] [[!]master] [[!]cert]
	             [[!]content] [[!]pcap] [[!]mirror] [$macro]|[!]*)

	        ReconnectSSL (yes|no)

	        # Connection options
	        DenyOCSP (yes|no)
	        Passthrough (yes|no)
	        CACert ca.crt
	        CAKey ca.key
	        ClientCert client.crt
	        ClientKey client.key
	        CAChain chain.crt
	        LeafCRLURL http://example.com/example.crl
	        DHGroupParams dh.pem
	        ECDHCurve prime256v1
	        SSLCompression (yes|no)
	        ForceSSLProto (ssl2|ssl3|tls10|tls11|tls12|tls13)
	        DisableSSLProto (ssl2|ssl3|tls10|tls11|tls12|tls13)
	        EnableSSLProto (ssl2|ssl3|tls10|tls11|tls12|tls13)
	        MinSSLProto (ssl2|ssl3|tls10|tls11|tls12|tls13)
	        MaxSSLProto (ssl2|ssl3|tls10|tls11|tls12|tls13)
	        Ciphers MEDIUM:HIGH
	        CipherSuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
	        RemoveHTTPAcceptEncoding (yes|no)
	        RemoveHTTPReferer (yes|no)
	        VerifyPeer (yes|no)
	        AllowWrongHost (yes|no)
	        UserAuth (yes|no)
	        UserTimeout 300
	        UserAuthURL https://192.168.0.1/userdblogin.php
	        ValidateProto (yes|no)
	        MaxHTTPHeaderSize 8192
	    }

	Structured filtering rules can be used to specify all possible connection 
	options to be selectively applied to matching connections, not just 
	per-proxyspec or globally. One line filtering rules cannot specify 
	connection options.

-   Add -B EnableSSLProto config option.


### SSLproxy 0.9.0 2021-10-21

-   Add filtering rules:

	    (Divert|Split|Pass|Block|Match)
	     ([from (
	         user (username[*]|$macro|*) [desc (desc[*]|$macro|*)]|
	         desc (desc[*]|$macro|*)|
	         ip (clientip[*]|$macro|*)|
	         *)]
	      [to (
	         (sni (servername[*]|$macro|*)|
	          cn (commonname[*]|$macro|*)|
	          host (host[*]|$macro|*)|
	          uri (uri[*]|$macro|*)|
	          ip (serverip[*]|$macro|*)) [port (serverport[*]|$macro|*)]|
	         port (serverport[*]|$macro|*)|
	         *)]
	      [log ([[!]connect] [[!]master] [[!]cert]
	            [[!]content] [[!]pcap] [[!]mirror] [$macro]|[!]*)]
	      |*) [# comment]

-   Add Define config option for defining macros to be used in filtering rules.
-   Add Include config option for loading configuration from an include file.
-   Add -Q test config option.
-   Various fixes and improvements.

    Note: The UTMFW project provides the SSLproxy Rule Editor, SPRE, which can 
    be used to configure proxyspecs, filtering rules, and options, similar to 
    the PF Rule Editor, PFRE, for OpenBSD/pf.


### SSLproxy 0.8.4 2021-08-29

-   Add split mode of operation similar to SSLsplit. In split mode, packets 
    are not diverted to listening programs, effectively making SSLproxy behave 
    like SSLsplit. Split mode can be defined globally or per-proxyspec.


### SSLproxy 0.8.3 2021-02-11

-   Improve UserAuth user control lists.
-   Improve documentation.


### SSLproxy 0.8.2 2020-12-14

-   Add DivertUsers and PassUsers options.
-   Allow mirroring without explicit target, copied from SSLsplit.
-   Various fixes and improvements.


### SSLproxy 0.8.1 2020-09-07

-   Partial support for TLS 1.3. No support for encrypted SNI yet. TLS 1.3 is 
    enabled by default depending on the version of OpenSSL.
-   Add -U CipherSuites option for TLS 1.3.
-   Add WITHOUT_USERAUTH switch, which removes the dependency on sqlite too.
-   Improve testproxy e2e tests.
-   Various fixes and improvements.


### SSLproxy 0.8.0 2020-05-24

-   Restructure source tree, create src and tests folders, move files
    and update make files accordingly.
-   Automate testproxy e2e tests, add them to travis config except for osx.
-   Improve verbose debug logs using common header fields to better identify
    connections. Create macro functions for fine* debug logs.
-   Switch from thrmgr to connection handling thread asap. Cleanly decouple
    code for thrmgr and conn handling threads. This prevents possible
    multithreading issues between thrmgr and conn handling threads. So remove
    thr mutex and BEV_OPT_THREADSAFE. The proxy core runs lockless now.
-   Offload thrmgr. Carry almost all conn init tasks from thrmgr to conn
    handling thread. Remove pending ssl conns list.
-   Convert linked lists to doubly linked lists. It is very fast to remove a
    list node now. And disable all conn ids unless debugging.
-   Fix readcb and writecb before connected, do not enable srvdst readcb until
    connected, enable read and write callbacks only after connected, disable
    unnecessary callbacks.
-   Do not use privsep to open socket for child listener.
-   Shut ssl conns down immediately after setting SSL_RECEIVED_SHUTDOWN,
    instead of trying to close them cleanly using low-level fd events and
    returned values from repeated calls to SSL_shutdown(), so remove
    ssl_shutdown_retry_delay and SSLShutdownRetryDelay, not used anymore.
    This also fixes stalled conn issues with autossl.
-   Disable autossl passthrough. Autossl passthrough crashes with signal 10.
-   Improve check unit tests and testproxy e2e tests.
-   Update with SSLsplit 0.5.5 changes.
-   Various fixes and improvements.


### SSLsplit 0.5.5 2019-08-30

-   Add -A option for specifying a default leaf certificate instead of
    generating it on the fly (issue #139).
-   Rename the following config file options for clarity and consistency:
    -   LeafCerts to LeafKey
    -   TargetCertDir to LeafCertDir
    -   CRL to LeafCRLURL
-   Increase the default RSA leaf key size to 2048 bits and force an OpenSSL
    security level of 0 in order to maximize interoperability in the default
    configuration.  OpenSSL with a security level of 2 or higher was rejecting
    our old default leaf key size of 1024 bits (issue #248).
-   Propagate the exit status of the privsep child process to the parent
    process and use 128+signal convention (issue #252).
-   Fix unexpected connection termination for certificates without a subject
    common name.
-   Fix TCP ports in packet mirroring mode (issue #247).
-   Fix certificate loading with LibreSSL 2.9.2 and later.
-   Add XNU headers for macOS Mojave 10.14.1 to 10.14.3.
-   Minor bugfixes and improvements.


### SSLsplit 0.5.4 2018-10-29

This release includes work sponsored by HackerOne.

-   Add PCAP content log modes (-X, -Y, -y) and a packet mirroring content log
    mode (-T, -I) to encapsulate decrypted traffic segments in emulated TCP, IP
    and Ethernet headers and write the result to PCAP files or send it to a
    packet capture host on the local network segment (issue #215, based on pull
    req #149 by @cihankom).
-   Suppress Expect-CT header in order to avoid Certificate Transparency log
    lookup failures (issue #205).
-   Add -x option for activating an OpenSSL engine (issue #204, pull req #206).
-   Add -f option for loading configuration from file, including a new manual
    page, sslsplit.conf(5) (pull req #193).
-   Bypass privilege separation overhead for when privileges are not actually
    dropped; this allows the use of `-u root` to actively prevent privilege
    separation and remove the associated IPC overhead (issue #222).
-   Add `sudotest` target for optional unit tests which require privileges to
    run successfully.
-   Fix crash when using LibreSSL (pull req #207).
-   Add XNU headers for macOS High Sierra 10.13.1 to 10.13.6.
-   Release sig PGP/GPG key rollover from 0xB5D3397E to 0xE1520675375F5E35.
-   Minor bugfixes and improvements.


### SSLsplit 0.5.3 2018-07-20

-   Add -a and -b for initial basic client certificate support (pull req #194
    by @naf419, issue #46).
-   Respect `SOURCE_DATE_EPOCH` for reproducible builds (pull req #192 by
    @anthraxx).
-   Sign using SHA-256 instead of SHA-1 when key type of server and key type
    of used CA certificate differ (issue #189).
-   Fix keyUsage to match the type of leaf key used instead of copying from
    upstream certificate (issue #195).
-   Fix build with OpenSSL 1.1.1 (pull req #186 by @sonertari, issue #183).
-   Fix build on FreeBSD 12 (patch-proc.c r436571 from FreeBSD ports).
-   Minor bugfixes and improvements.


### SSLsplit 0.5.2 2018-02-10

-   Add support for SSLv2 ClientHello handshake format for SSLv3/TLS
    connections and while there, essentially fixing autossl for clients using
    SSLv2 ClientHello handshake format with SSLv3/TLS (#185).
-   Suppress Upgrade header in order to prevent upgrading connections to
    WebSockets or HTTP/2 (#91).
-   Add -M for writing an SSLKEYLOGFILE compatible log file (issue #184).
-   Fix error handling for Darwin libproc functions (-i).
-   Fix session cache misses and failed unit tests on MIPS by fixing undefined
    behaviour in session cache hash functions (Debian #848919 and #851271).
-   Synthesize MAC addresses to avoid the requirement for root privileges and
    waiting for ARP timeouts on some platforms in log2pcap.py (issue #169).
-   Minor bugfixes and improvements.


### SSLsplit 0.5.1 2018-01-14

-   Dump master key in NSS key log format in debug mode, allowing decryption of
    SSL connections using Wireshark (issue #121).
-   Add support for DSA and ECDSA certificates using hash algorithms other than
    SHA-1.
-   Copy basicConstraints, keyUsage and extendedKeyUsage X509v3 extensions from
    the original certificate and only generate them anew if they were not
    present (issue #73).
-   Add -q to set the CRL distribution point on all forged certificates
    (pull req #159 by @antalos).
-   Add IPv6 support to netfilter NAT engine (pull req #179 by @armakar).
-   Extend -L content logging with EOF message to allow log parsers to figure
    out when a connection ends (issue #128 by @mattes).  Note that log parsers
    need to be adjusted to handle the new EOF message.
-   Fix potential segfaults in src.bev/dst.bev (pull req #174 by @sonertari).
-   Fix SSL connections that result from autossl to shutdown cleanly.
-   Fix data processing when EOF is received before all incoming data has been
    processed.
-   Fix multiple signal handling issues in the privilege separation parent
    which led to the parent process being killed ungracefully or being stuck
    in wait() while still having signals queued up for forwarding to the child
    process (issue #137).
-   No longer assume an out of memory condition when a certificate contains
    neither a CN nor a subjectAltName extension.
-   Fix parallel make build (-j) for the test target (issue #140).
-   Do not set owner and group if install target is called by unprivileged
    user (pull req #141 by @cgroschupp).
-   Fix build with OpenSSL 1.1.0 and later (pull req #154 by @hillu, #156 by
    @pduldig-at-tw and issue #148).
-   Add XNU headers for Mac OS X El Capitan 10.11.3 to 10.11.6, Sierra 10.12
    to 10.12.6 and High Sierra 10.13; fix headers for Mac OS X 10.6 to 10.6.8.
-   Minor bugfixes and improvements.


### SSLsplit 0.5.0 2016-03-27

-   Generically support STARTTLS through the new autossl proxyspec type that
    upgrades a TCP connection to SSL/TLS when a ClientHello message is seen
    (based on contribution by @RichardPoole42, pull req #87).
-   Add separate src/dst host and port format specifiers %S, %p, %D and %q
    to -F (pull req #74 by @AdamJacobMuller).
-   Add options -w and -W to write generated leaf key, original and forged
    certificates to disk (issue #67 by @psychomario).
-   Add signal SIGUSR1 to re-open long-living -l/-L log files (issue #52).
-   Add contributed -L log parsing scripts to extra/, including conversion to
    PCAP using emulated IP and TCP headers (contributed by @mak, issue #27).
-   Enable full-strength DHE and ECDHE by default, even for non-RSA leaf keys,
    in order to avoid weak cipher warnings from browsers (issue #119).
-   Use the same hash algorithm in signatures on forged certificates as the
    original certificates use, instead of always using SHA-1.
-   Removed all references to SHA-1 and small key RSA root CA keys from
    documentation, examples and unit testing (issue #83).
-   Introduce privilege separation architecture with privileged parent process
    and unprivileged child process; all files are now opened with the
    privileges of the user running SSLsplit; arguments to -S/-F are no longer
    relative to the chroot() if used with the -j option.
-   Filenames generated by -S and -F %d and %s changed from [host]:port to
    host,port format and using underscore instead of colon in IPv6 addresses
    in order to be NTFS clean (issue #69).
-   Connect log format: host and port are now separate fields (issues #69 #74).
-   Only initialize DNS subsystems when DNS lookups are actually needed by the
    loaded proxy specifications (related to issue #104).
-   Removed the non-standard word "unmodified" from the 2-clause BSD license.
-   Warn when an OpenSSL version mismatch is detected (issue #88).
-   Add XNU headers for OS X 10.11 El Capitan (issue #116).
-   Fix EV_READ event re-enable bug that could lead to stalled connections
    after throttling one direction (issue #109).
-   Fix build with LibreSSL that lacks recent OpenSSL API additions.
-   Fix build with OpenSSL versions that had SSLv3 support removed.
-   Fix a rare segmentation fault upon receiving EOF on the outbound connection
    while it has not been established yet (patch by @eunsoopark, issue #124).
-   Fix SSL sessions to actually time out (patch by @eunsoopark, issue #115).
-   Fix passthrough mode with -t and an empty directory (issue #92).
-   Minor bugfixes and improvements.


### SSLsplit 0.4.11 2015-03-16

-   Fix loading of certificate chains with OpenSSL 1.0.2 (issue #79).
-   Fix build on Mac OS X 10.10.2 by improving XNU header selection.


### SSLsplit 0.4.10 2014-11-28

-   Add option -F to log to separate files with printf-style % directives,
    including process information for connections originating on the same
    system when also using -i (pull reqs #36, #53, #54, #55 by @landonf).
-   Add option -i to look up local process owning a connection for logging to
    connection log; initial support on Mac OS X (by @landonf) and FreeBSD.
-   Add option -r to force a specific SSL/TLS protocol version (issue #30).
-   Add option -R to disable specific SSL/TLS protocol versions (issue #30).
-   Disallow -u with pf proxyspecs on Mac OS X because Apple restricts
    ioctl(/dev/pf) to root even on an fd initially opened by root (issue #65).
-   Extend the certificate loading workaround for OpenSSL 1.0.0k and 1.0.1e
    also to OpenSSL 0.9.8y; fixes cert loading crash due to bug in in OpenSSL.
-   Extend Mac OS X pf support to Yosemite 10.10.1.
-   Fix startup memory leaks in key/cert loader (pull req #56 by @wjjensen).
-   Replace WANT_SSLV2_CLIENT and WANT_SSLV2_SERVER build knobs with a single
    WITH_SSLV2 build knob.
-   Minor bugfixes and improvements.


### SSLsplit 0.4.9 2014-11-03

-   Filter out HSTS response header to allow users to accept untrusted certs.
-   Build without SSLv2 support by default (issue #26).
-   Add primary group override (-m) when dropping privileges to an
    unprivileged user (pull req #35 by @landonf).
-   Support pf on Mac OS X 10.10 Yosemite and fix segmentation fault if
    no NAT engine is available (pull req #32 by @landonf).
-   Support DESTDIR and MANDIR in the build (pull req #34 by @swills).
-   No longer chroot() to /var/empty by default if run by root, in order to
    prevent breaking -S and sni proxyspecs (issue #21).
-   Load -t certificates before dropping privileges (issues #19 and #20).
-   Fix segmentation fault when using -t without a CA.
-   Minor bugfixes and improvements.


### SSLsplit 0.4.8 2014-01-15

-   Filter out Alternate-Protocol response header to suppress SPDY/QUIC.
-   Add experimental support for pf on Mac OS X 10.7+ (issue #15).
-   Also build ipfw NAT engine if pf is detected to support pf divert-to.
-   Unit tests (make test) no longer require Internet connectivity.
-   Always use SSL_MODE_RELEASE_BUFFERS when available, which lowers the per
    connection memory footprint significantly when using OpenSSL 1.0.0+.
-   Fix memory corruption after the certificate in the cache had to be updated
    during connection setup (issue #16).
-   Fix file descriptor leak in passthrough mode (-P) after SSL errors.
-   Fix OpenSSL data structures memory leak on certificate forgery.
-   Fix segmentation fault on connections without SNI hostname, caused by
    compilers optimizing away a NULL pointer check (issue #14).
-   Fix thread manager startup failure under some circumstances (issue #17).
-   Fix segmentation faults if thread manager fails to start (issue #10).


### SSLsplit 0.4.7 2013-07-02

-   Fix remaining threading issues in daemon mode.
-   Filter HPKP header lines from HTTP(S) response headers in order to prevent
    public key pinning based on draft-ietf-websec-key-pinning-06.
-   Add HTTP status code and content-length to connection log.


### SSLsplit 0.4.6 2013-06-03

-   Fix fallback to passthrough (-P) when no matching certificate is found
    for a connection (issue #9).
-   Work around segmentation fault when loading certificates caused by a bug
    in OpenSSL 1.0.0k and 1.0.1e.
-   Fix binding to ports < 1024 with default settings (issue #8).


### SSLsplit 0.4.5 2012-11-07

-   Add support for 2048 and 4096 bit Diffie-Hellman.
-   Fix syslog error messages (issue #6).
-   Fix threading issues in daemon mode (issue #5).
-   Fix address family check in netfilter NAT lookup (issue #4).
-   Fix build on recent glibc systems (issue #2).
-   Minor code and build process improvements.


### SSLsplit 0.4.4 2012-05-11

-   Improve OCSP denial for GET based OCSP requests.
-   Default elliptic curve is now 'secp160r2' for better ECDH performance.
-   More user-friendly handling of -c, -k and friends.
-   Unit test source code renamed from *.t to *.t.c to prevent them from being
    misdetected as perl instead of c by Github et al.
-   Minor bugfixes.


### SSLsplit 0.4.3 2012-04-22

-   Add generic OCSP denial (-O).  OCSP requests transmitted over HTTP or HTTPS
    are recognized and denied with OCSP tryLater(3) responses.
-   Minor bugfixes.


### SSLsplit 0.4.2 2012-04-13

First public release.


