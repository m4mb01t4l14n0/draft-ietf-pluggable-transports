---
title: Enabling Network Traffic Obfuscation: Pluggable Transports IPC
abbrev: Pluggable Transports
docname: draft-irtf-oliver-pt-ipc
category: info
category: Computer-Communication Networks: Network Protocols 
category: Computer-Communication Networks: General—Security and protection 
category: Computers And Society: Public Policy Issues—Privacy

ipr: trust200902
area: General
workgroup: Transport Working Group
keyword: Internet-Draft
keyword: Tor
keyword: pluggable transport
keyword: active probing
keyword: traffic analysis
keyword: censorship
keyword: circumvention


stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: "David Oliver"
    name: "David M. Oliver"
    organization: "Guardian Project"
    email: david@guardianproject.info
    uri: https://guardianproject.info

normative:
  RFC2119:

informative:



--- abstract

Pluggable Transports (PTs) are a mechanism enabling the rapid development and 
deployment of network traffic obfuscation techniques used to circumvent
surveillance and censorship. This specification does
not define or limit the techniques themselves, but rather focuses 
on the startup, shutdown, and inter-process communication mechanisms 
required to make these technologies interoperable with applications.

--- middle

# Introduction

The increased interest in network traffic obfuscation technologies mirrors the 
increase in usage Deep Packet Inspection (DPI) to actively monitor the content 
of application data in addition to that data's routing information.  Deep Packet 
Inspection inspects each packet based on the header of its request and the 
data it carries. It can identify the type of protocol the connection is 
using even if it was encrypted. DPI is not a mechanism to decrypt what is 
inside packets but to identify the ‘protocol’ or the application it represents.

Deep packet inspection has become the prime tool of censors and surveillance entities who 
block, log and/or traffic-shape access to sites and services they deem undesirable.  
As deep packet inspection has become more routine, the sophistication of monitoring 
has increased to include active probing that fingerprints and classifies application 
protocols.  Thus, even as conventional care in application design has improved
(via encryption and other protocol design features that encourage privacy), 
network traffic is still under attack.

The techniques of network monitoring are changing and improving
day by day.  The development of traffic obfuscation techniques that foil these 
efforts is slowed by the lack of common agreement on how these techniques are invoked, 
made easily interoperable with applications, and deployed quickly.  This 
specification addresses those issues.

	<!-- taken largely from PT1 spec -->
This specification describes a method for decoupling protocol-level obfuscation from 
an application's client/server code, in a manner that promotes rapid development 
of obfuscation/circumvention tools and promotes reuse across privacy tools such as
VPNs and secure proxies.

This decoupling is accomplished by utilizing helper sub-processes that implement the 
necessary forward/reverse proxy servers that handle the censorship circumvention, 
with a well defined and standardized configuration and management interface. Any 
application code that implements the interfaces as specified in this document 
will be able to use all spec compliant Pluggable Transports.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# Background

We define an Internet censor as any network intermediary that seeks to block, divert or 
traffic-manage Internet network connections for the purpose of eliminating, frustrating
and/or logging access to Internet resources that have been deemed (by the censor) 
to be undesirable (either on a temporary or permanent basis).  A variety of 
techniques are commonly applied by Internet censors to block such traffic.  These include:

1. DNS Blocking
2. IP Blocking
3. Protocol and Port Blocking

These techniques are applicable to a connection's metadata (IP routing information)
and do not require inspecting the connection's datastream.

DPI, in contrast, actually looks at the connection's datastream - often, specifically, 
the initial data elements in the stream (or within blocks of the stream).  These 
elements of the stream can contain clues 
as to the application-level protocol employed, even when the data itself is 
encrypted.  With repeated exposure, these clues ("fingerprints") can be learned by
the censor and (along with the routing information) used to block or divert 
targeted traffic.  

A defense against this type of active probing is traffic obfuscation - disguising
the application data itself in a manner that is less-easily fingerprinted.  But in
early experiments, it quickly became clear that repeated use of the same 
obfuscation technique would, itself, be learned. Methods were developed 
by which a single obfuscation technique could transform on its own [cite FTE 
proxy, ScrambleSuit].  But, this approach proved expensive in terms of 
computational load.  Interest gathered in solving this problem and as more ideas
arose so to did the need for a mechanism supporting rapid deploying of new 
obfuscation techniques.  

While intense work on network traffic obfuscation commenced initially and continues within
the Tor Project (and across a wider set of external parties using Tor as a vehicle 
for research), vendors of other privacy-enhancing software (such as VPNs) quickly found 
their products also foiled by DPI.  Thus, it becomes important to see
transport plug-ability as a mechanism implemented in a manner independent of a 
specific product or service.  The notion of "Pluggable Transports" (PT) was born from
these requirements.


# Architecture Overview

	<!-- from the PT1 spec -->

     +------------+                    +---------------------------+
     | Client App +-- Local Loopback --+ PT Client (SOCKS Proxy)   +
     +------------+                    +---------------------------+
                                            [ Obfuscation Protocol ]--+
                                                                      |
                 Public Internet (Obfuscated/Transformed traffic) ==&gt; |
                                                                      |
                                            [ Obfuscation Protocol ]--+
     +------------+                    +---------------------------+ 
     | Server App +-- Local Loopback --+ PT Server (Reverse Proxy) +
     +------------+                    +---------------------------+

On the client's host, the PT Client software exposes a SOCKS proxy
[RFC1928] to the client application, and obfuscates or otherwise
transforms traffic before forwarding it to the server's host.

On the server's host, the PT Server software exposes a reverse proxy
that accepts connections from PT Clients, and handles reversing the
obfuscation/transformation applied to traffic, before forwarding it
to the actual server software.  An optional lightweight protocol
exists to facilitate communicating connection meta-data that would
otherwise be lost such as the source IP address and port
[EXTORPORT].

All PT instances are configured by the respective parent process via
a set of standardized environment variables (3.2) that are set at
launch time, and report status information back to the parent via
writing output in a standardized format to stdout (3.3).

Each invocation of a PT MUST be either a client OR a server.

All PT client forward proxies MUST support either SOCKS 4 or SOCKS 5,
and SHOULD prefer SOCKS 5 over SOCKS 4.

# Specification

	<!-- from PT1 spec -->

## Workflow
	
Pluggable Transport proxies follow the following workflow throughout their lifespan.

1. Parent process sets the required environment values (3.2) and launches the PT proxy as a sub-process (fork()/exec()).

2. The PT Proxy determines the versions of the PT specification supported by the parent"TOR_PT_MANAGED_TRANSPORT_VER" (3.2.1)
  2.1 If there are no compatible versions, the PT proxy writes a "VERSION-ERROR" message (3.3.1) to stdout and terminates.
  2.2 If there is a compatible version, the PT proxy writes a "VERSION" message (3.3.1) to stdout.

3. The PT Proxy parses the rest of the environment values.
  3.1 If the environment values are malformed, or otherwise invalid, the PT proxy writes a "ENV-ERROR" message (3.3.1) to stdout and terminates.
  3.2 Determining if it is a client side forward proxy or a server side reverse proxy can be done via examining the "TOR_PT_CLIENT_TRANSPORTS" and "TOR_PT_SERVER_TRANSPORTS" environment variables.

4. (Client only) If there is an upstream proxy specified via "TOR_PT_PROXY" (3.2.2), the PT proxy validates the URI provided.
  4.1 If the upstream proxy is unusable, the PT proxy writes a "PROXY-ERROR" message (3.3.2) to stdout and terminates.
  4.2 If there is a supported and well-formed upstream proxy the PT proxy writes a "PROXY DONE" message (3.3.2) to stdout.

5. The PT Proxy initializes the transports and reports the status via stdout (3.3.2, 3.3.3)

6. The PT Proxy forwards and transforms traffic as appropriate.

7. Upon being signaled to terminate by the parent process (3.4), the PT Proxy gracefully shuts down.

### Pluggable Transport Naming

Pluggable Transport names serve as unique identifiers, and every PT MUST have a unique name.

PT names MUST be valid C identifiers.  PT names MUST begin with a letter 
or underscore, and the remaining characters MUST be ASCII letters, numbers or underscores.  No length limit is imposed.

PT names MUST satisfy the regular expression "[a-zA-Z_][a-zA-Z0-9_]*".

### Pluggable Transport Configuration Environment Variables

   All Pluggable Transport proxy instances are configured by their
   parent process at launch time via a set of well defined
   environment variables.

   The "TOR_PT_" prefix is used for namespacing reasons and does not
   indicate any relations to Tor, except for the origins of this
   specification.

#### Common Environment Variables

When launching either a client or server Pluggable Transport proxy,
the following common environment variables MUST be set.

	TOR_PT_MANAGED_TRANSPORT_VER

Specifies the versions of the Pluggable Transport specification
the parent process supports, delimited by commas.  All PTs MUST
accept any well-formed list, as long as a compatible version is
present.

Valid versions MUST consist entirely of non-whitespace,
non-comma printable ASCII characters.

The version of the Pluggable Transport specification as of this
document is "1".

Example:

	TOR_PT_MANAGED_TRANSPORT_VER=1,1a,2b,this_is_a_valid_ver

  	TOR_PT_STATE_LOCATION

Specifies an absolute path to a directory where the PT is
allowed to store state that will be persisted across
invocations.  The directory is not required to exist when
the PT is launched, however PT implementations SHOULD be
able to create it as required.

PTs MUST only store files in the path provided, and MUST NOT
create or modify files elsewhere on the system.

Example:

	TOR_PT_STATE_LOCATION=/var/lib/tor/pt_state/

	TOR_PT_EXIT_ON_STDIN_CLOSE

Specifies that the parent process will close the PT proxy's
standard input (stdin) stream to indicate that the PT proxy
should gracefully exit.

PTs MUST NOT treat a closed stdin as a signal to terminate
unless this environment variable is set to `1`.

PTs SHOULD treat stdin being closed as a signal to gracefully
terminate if this environment variable is set to `1`.

Example:

	TOR_PT_EXIT_ON_STDIN_CLOSE=1

#### Pluggable Transport Client Environment Variables

Client-side Pluggable Transport forward proxies are configured via the following environment variables.

	TOR_PT_CLIENT_TRANSPORTS

 Specifies the PT protocols the client proxy should initialize,
 as a comma separated list of PT names.

 PTs SHOULD ignore PT names that it does not recognize.

 Parent processes MUST set this environment variable when
 launching a client-side PT proxy instance.

 Example:

	TOR_PT_CLIENT_TRANSPORTS=obfs2,obfs3,obfs4

	TOR_PT_PROXY

 Specifies an upstream proxy that the PT MUST use when making
 outgoing network connections.  It is a URI [RFC3986] of the
 format:

	<proxy_type>://[<user_name>[:password][@]<ip>:<port>.

 The `TOR_PT_PROXY` environment variable is OPTIONAL and
 MUST be omitted if there is no need to connect via an
 upstream proxy.

Examples:

	TOR_PT_PROXY=socks5://tor:test1234@198.51.100.1:8000
	TOR_PT_PROXY=socks4a://198.51.100.2:8001
	TOR_PT_PROXY=http://198.51.100.3:443

#### Pluggable Transport Server Environment Variables

Server-side Pluggable Transport reverse proxies are configured via the following environment variables.

	TOR_PT_SERVER_TRANSPORTS

 Specifies the PT protocols the server proxy should initialize,
 as a comma separated list of PT names.

 PTs SHOULD ignore PT names that it does not recognize.

 Parent processes MUST set this environment variable when
 launching a server-side PT reverse proxy instance.

 Example:

	TOR_PT_SERVER_TRANSPORTS=obfs3,scramblesuit

	TOR_PT_SERVER_TRANSPORT_OPTIONS

 Specifies per-PT protocol configuration directives, as a
 semicolon-separated list of &lt;key&gt;:&lt;value&gt; pairs, where &lt;key&gt;
 is a PT name and &lt;value&gt; is a k=v string value with options
 that are to be passed to the transport.

 Colons, semicolons, and backslashes MUST be
 escaped with a backslash.

 If there are no arguments that need to be passed to any of
 PT transport protocols, "TOR_PT_SERVER_TRANSPORT_OPTIONS"
 MAY be omitted.

 Example:

	TOR_PT_SERVER_TRANSPORT_OPTIONS=scramblesuit:key=banana;automata:rule=110;automata:depth=3

Will pass to 'scramblesuit' the parameter 'key=banana' and to
'automata' the arguments 'rule=110' and 'depth=3'.

	TOR_PT_SERVER_BINDADDR

A comma separated list of &lt;key&gt;-&lt;value&gt; pairs, where &lt;key&gt; is
a PT name and &lt;value&gt; is the &lt;address&gt; : &lt;port&gt; on which it
should listen for incoming client connections.

The keys holding transport names MUST be in the same order as
they appear in "TOR_PT_SERVER_TRANSPORTS".

The &lt;address&gt; MAY be a locally scoped address as long as port
forwarding is done externally.

The &lt;address&gt;:&lt;port&gt; combination MUST be an IP address
supported by `bind()`, and MUST NOT be a host name.

Applications MUST NOT set more than one &lt;address&gt;:&lt;port&gt; pair
per PT name.

If there is no specific &lt;address&gt;:&lt;port&gt; combination to be
configured for any transports, "TOR_PT_SERVER_BINDADDR" MAY
be omitted.

Example:

	TOR_PT_SERVER_BINDADDR=obfs3-198.51.100.1:1984,scramblesuit-127.0.0.1:4891

	TOR_PT_ORPORT

Specifies the destination that the PT reverse proxy should forward
traffic to after transforming it as appropriate, as an
&lt;address&gt;:&lt;port&gt;.

Connections to the destination specified via "TOR_PT_ORPORT"
MUST only contain application payload.  If the parent process
requires the actual source IP address of client connections
(or other metadata), it should set "TOR_PT_EXTENDED_SERVER_PORT"
instead.

Example:

	TOR_PT_ORPORT=127.0.0.1:9001

	TOR_PT_EXTENDED_SERVER_PORT

Specifies the destination that the PT reverse proxy should
forward traffic to, via the Extended ORPort protocol [EXTORPORT]
as an &lt;address&gt;:&lt;port&gt;.

The Extended ORPort protocol allows the PT reverse proxy to
communicate per-connection metadata such as the PT name and
client IP address/port to the parent process.

If the parent process does not support the ExtORPort protocol,
it MUST set "TOR_PT_EXTENDED_SERVER_PORT" to an empty string.

Example:

	TOR_PT_EXTENDED_SERVER_PORT=127.0.0.1:4200

	TOR_PT_AUTH_COOKIE_FILE

Specifies an absolute filesystem path to the Extended ORPort
authentication cookie, required to communicate with the
Extended ORPort specified via "TOR_PT_EXTENDED_SERVER_PORT".

If the parent process is not using the ExtORPort protocol for
incoming traffic, "TOR_PT_AUTH_COOKIE_FILE" MUST be omitted.

Example:

      TOR_PT_AUTH_COOKIE_FILE=/var/lib/tor/extended_orport_auth_cookie

## Pluggable Transport To Parent Process Communication

All Pluggable Transport Proxies communicate to the parent process via writing NL-terminated lines to stdout.  The line metaformat is:

	<Line> ::= <Keyword> <OptArgs> <NL>
	<Keyword> ::= <KeywordChar> | <Keyword> <KeywordChar>
	<KeywordChar> ::= <any US-ASCII alphanumeric, dash, and underscore>
	<OptArgs> ::= <Args>*
	<Args> ::= <SP> <ArgChar> | <Args> <ArgChar>
	<ArgChar> ::= <any US-ASCII character but NUL or NL>
	<SP> ::= <US-ASCII whitespace symbol (32)>
	<NL> ::= <US-ASCII newline (line feed) character (10)>

The parent process MUST ignore lines received from PT proxies with unknown keywords.

### Common Messages

When a PT proxy first starts up, it must determine which version
of the Pluggable Transports Specification to use to configure
itself.

It does this via the "TOR_PT_MANAGED_TRANSPORT_VER" (3.2.1)
environment variable which contains all of the versions supported
by the application.

Upon determining the version to use, or lack thereof, the PT
proxy responds with one of two messages.

	VERSION-ERROR <ErrorMessage>

The "VERSION-ERROR" message is used to signal that there was
no compatible Pluggable Transport Specification version
present in the "TOR_PT_MANAGED_TRANSPORT_VER" list.

The &lt;ErrorMessage&gt; SHOULD be set to "no-version" for
historical reasons but MAY be set to a useful error message
instead.

PT proxies MUST terminate after outputting a "VERSION-ERROR"
message.

Example:

	VERSION-ERROR no-version

	VERSION <ProtocolVersion>

The "VERSION" message is used to signal the Pluggable Transport
Specification version (as in "TOR_PT_MANAGED_TRANSPORT_VER")
that the PT proxy will use to configure it's transports and
communicate with the parent process.

The version for the environment values and reply messages
specified by this document is "1".

PT proxies MUST either report an error and terminate, or output
a "VERSION" message before moving on to client/server proxy
initialization and configuration.

Example:

	VERSION 1

After version negotiation has been completed the PT proxy must
then validate that all of the required environment variables are
provided, and that all of the configuration values supplied are
well formed.

At any point, if there is an error encountered related to
configuration supplied via the environment variables, it MAY
respond with an error message and terminate.

	ENV-ERROR <ErrorMessage>

The "ENV-ERROR" message is used to signal the PT proxy's
failure to parse the configuration environment variables (3.2).

The &lt;ErrorMessage&gt; SHOULD consist of a useful error message
that can be used to diagnose and correct the root cause of
the failure.

PT proxies MUST terminate after outputting a "ENV-ERROR"
message.

Example:

	ENV-ERROR No TOR_PT_AUTH_COOKIE_FILE when TOR_PT_EXTENDED_SERVER_PORT set

### Pluggable Transport Client Messages

After negotiating the Pluggable Transport Specification version,
PT client proxies MUST first validate "TOR_PT_PROXY" (3.2.2) if
it is set, before initializing any transports.

Assuming that an upstream proxy is provided, PT client proxies
MUST respond with a message indicating that the proxy is valid,
supported, and will be used OR a failure message.

	PROXY DONE

 The "PROXY DONE" message is used to signal the PT proxy's
 acceptance of the upstream proxy specified by "TOR_PT_PROXY".

	PROXY-ERROR <ErrorMessage>

 The "PROXY-ERROR" message is used to signal that the upstream
 proxy is malformed/unsupported or otherwise unusable.

 PT proxies MUST terminate immediately after outputting a
 "PROXY-ERROR" message.

 Example:

	PROXY-ERROR SOCKS 4 upstream proxies unsupported.

After the upstream proxy (if any) is configured, PT clients then
iterate over the requested transports in "TOR_PT_CLIENT_TRANSPORTS"
and initialize the listeners.

For each transport initialized, the PT proxy reports the listener
status back to the parent via messages to stdout.

	CMETHOD <transport> <'socks4','socks5'> <address:port>

The "CMETHOD" message is used to signal that a requested
PT transport has been launched, the protocol which the parent
should use to make outgoing connections, and the IP address
and port that the PT transport's forward proxy is listening on.

Example:

	CMETHOD trebuchet socks5 127.0.0.1:19999

	CMETHOD-ERROR <transport> <ErrorMessage>

The "CMETHOD-ERROR" message is used to signal that
requested PT transport was unable to be launched.

Example:

	CMETHOD-ERROR trebuchet no rocks available

Once all PT transports have been initialized (or have failed), the
PT proxy MUST send a final message indicating that it has finished
initializing.

	CMETHODS DONE

The "CMETHODS DONE" message signals that the PT proxy has
finished initializing all of the transports that it is capable
of handling.

Upon sending the "CMETHODS DONE" message, the PT proxy
initialization is complete.

Notes:

 - Unknown transports in "TOR_PT_CLIENT_TRANSPORTS" are ignored
   entirely, and MUST NOT result in a "CMETHOD-ERROR" message.
   Thus it is entirely possible for a given PT proxy to
   immediately output "CMETHODS DONE".

 - Parent processes MUST handle "CMETHOD"/"CMETHOD-ERROR"
   messages in any order, regardless of ordering in
   "TOR_PT_CLIENT_TRANSPORTS".

### Pluggable Transport Server Messages

PT server reverse proxies iterate over the requested transports
in "TOR_PT_CLIENT_TRANSPORTS" and initialize the listeners.

For each transport initialized, the PT proxy reports the listener
status back to the parent via messages to stdout.

	SMETHOD <transport> <address:port> [options]

The "SMETHOD" message is used to signal that a requested
PT transport has been launched, the protocol which will be
used to handle incoming connections, and the IP address and
port that clients should use to reach the reverse-proxy.

If there is a specific &lt;address:port&gt; provided for a given
PT transport via "TOR_PT_SERVER_BINDADDR", the transport
MUST be initialized using that as the server address.

The OPTIONAL 'options' field is used to pass additional
per-transport information back to the parent process.

The currently recognized 'options' are:

  ARGS:[<Key>=<Value>]+[<Key>=<Value>]

 The "ARGS" option is used to pass additional key/value
 formatted information that clients will require to use
 the reverse proxy.

 Equal signs and commas MUST be escaped with a backslash.

 Tor: The ARGS are included in the transport line of the
 Bridge's extra-info document.

Examples:

	SMETHOD trebuchet 198.51.100.1:19999
	SMETHOD rot_by_N 198.51.100.1:2323 ARGS:N=13

	SMETHOD-ERROR <transport> <ErrorMessage>

The "SMETHOD-ERROR" message is used to signal that
requested PT transport reverse proxy was unable to be
launched.

Example:

	SMETHOD-ERROR trebuchet no cows available

Once all PT transports have been initialized (or have failed), the
PT proxy MUST send a final message indicating that it has finished
initializing.

	SMETHODS DONE

The "SMETHODS DONE" message signals that the PT proxy has
finished initializing all of the transports that it is capable
of handling.

Upon sending the "SMETHODS DONE" message, the PT proxy
initialization is complete.

### Pluggable Transport Log Message

This message is for a client or server PT to be able to signal back to the
parent process via stdout or stderr any log messages.

A log message can be any kind of messages (human readable) that the PT
sends back so the parent process can gather information about what is going
on in the child process. It is not intended for the parent process to parse
and act accordingly but rather a message used for plain logging.

For example, the tor daemon logs those messages at the Severity level and
sends them onto the control port using the PT_LOG (see control-spec.txt)
event so any third part can pick them up for debugging.

The format of the message:

	LOG SEVERITY=Severity MESSAGE=Message

The SEVERITY value indicate at which logging level the message applies.
The accepted values for &lt;Severity&gt; are: error, warning, notice, info, debug

The MESSAGE value is a human readable string formatted by the PT. The
&lt;Message&gt; contains the log message which can be a String or CString (see
section 2 in control-spec.txt).

Example:

	LOG SEVERITY=debug MESSAGE="Connected to bridge A"

### Pluggable Transport Status Message

This message is for a client or server PT to be able to signal back to the
parent process via stdout or stderr any status messages.

The format of the message:

	STATUS TRANSPORT=Transport <K_1>=<V_1> [<K_2>=<V_2>, ...]

The TRANSPORT value indicate a hint on what the PT is such has the name or
the protocol used for instance. As an example, obfs4proxy would use
"obfs4". Thus, the Transport value can be anything the PT itself defines
and it can be a String or CString (see section 2 in control-spec.txt).

The &lt;K_n&gt;=&lt;V_n&gt; values are specific to the PT and there has to be at least
one. They are messages that reflects the status that the PT wants to
report. &lt;V_n&gt; can be a String or CString.

Examples (fictional):

	STATUS TRANSPORT=obfs4 ADDRESS=198.51.100.123:1234 CONNECT=Success
	STATUS TRANSPORT=obfs4 ADDRESS=198.51.100.222:2222 CONNECT=Failed FINGERPRINT=&lt;Fingerprint&gt; ERRSTR="Connection refused"
	STATUS TRANSPORT=trebuchet ADDRESS=198.51.100.15:443 PERCENT=42

## Pluggable Transport Shutdown

The recommended way for Pluggable Transport using applications and Pluggable Transports to handle graceful shutdown is as follows.

1. (Parent) Set "TOR_PT_EXIT_ON_STDIN_CLOSE" (3.2.1) when
launching the PT proxy, to indicate that stdin will be used
for graceful shutdown notification.

2. (Parent) When the time comes to terminate the PT proxy:

  1. Close the PT proxy's stdin.
  2. Wait for a "reasonable" amount of time for the PT to exit.
  3. Attempt to use OS specific mechanisms to cause graceful PT shutdown (eg: 'SIGTERM')
  4. Use OS specific mechanisms to force terminate the PT (eg: 'SIGKILL', 'ProccessTerminate()').

    - PT proxies SHOULD monitor stdin, and exit gracefully when it is closed, if the parent supports that behavior.
    - PT proxies SHOULD handle OS specific mechanisms to gracefully terminate (eg: Install a signal handler on 'SIGTERM' that causes cleanup and a graceful shutdown if able).
    - PT proxies SHOULD attempt to detect when the parent has terminated (eg: via detecting that it's parent process ID has changed on U*IX systems), and gracefully terminate.

## Pluggable Transport Client Per-Connection Arguments

Certain PT transport protocols require that the client provides
per-connection arguments when making outgoing connections.  On
the server side, this is handled by the "ARGS" optional argument
as part of the "SMETHOD" message.

On the client side, arguments are passed via the authentication
fields that are part of the SOCKS protocol.

First the "&lt;Key&gt;=&lt;Value&gt;" formatted arguments MUST be escaped,
such that all backslash, equal sign, and semicolon characters
are escaped with a backslash.

Second, all of the escaped are concatenated together.

Example:

	shared-secret=rahasia;secrets-file=/tmp/blob

Lastly the arguments are transmitted when making the outgoing
connection using the authentication mechanism specific to the
SOCKS protocol version.

 - In the case of SOCKS 4, the concatenated argument list is transmitted in the "USERID" field of the "CONNECT" request.
 - In the case of SOCKS 5, the parent process must negotiate "Username/Password" authentication [RFC1929], and transmit the arguments encoded in the "UNAME" and "PASSWD" fields.
 - If the encoded argument list is less than 255 bytes in length, the "PLEN" field must be set to "1" and the "PASSWD" field must contain a single NUL character.

# Anonymity Considerations

	<!-- from PT1 spec -->
When designing and implementing a Pluggable Transport, care
should be taken to preserve the privacy of clients and to avoid
leaking personally identifying information.

Examples of client related considerations are:
- Not logging client IP addresses to disk.
- Not leaking DNS addresses except when necessary.
- Ensuring that "TOR_PT_PROXY"'s "fail closed" behavior is implemented correctly.

Additionally, certain obfuscation mechanisms rely on information such as the 
server IP address/port being confidential, so clients also need to take 
care to preserve server side information confidential when applicable.

# Security Considerations

	<!-- taken from SOCKS RFC description -->
This document describes a protocol for the application-layer traversal of data
over IP networks as a thin veneer over the SOCKS 5 protocol.  The security of 
our network traversal is highly dependent on the particular authentication 
and encapsulation methods provided in each particular Pluggable Transport 
implementation, as managed by the SOCKS client, Pluggable Transport client, 
Pluggable Transport server, and SOCKS server.


# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

This specification draws heavily from prior iterations on network traffic
obfuscation done within the Tor Project [TOR] by Jacob Appelbaum, 
Nick Mathewson, and George Kadianakis. As this work broadened to include 
developers outside of Tor, we thank the development teams at Lantern, Operator Foundation, Psiphon and TunnelBear

# References
{:numbered="true"}

[TOR]
[PT1] Pluggable Transports Specification (Version 1) 
[PT2] Pluggable Transports Specification (Version 2.0.2) 
[PTI] https://pluggabletransports.info/

[RFC2119]     Bradner, S., "Key words for use in RFCs to Indicate
                 Requirement Levels", BCP 14, RFC 2119, March 1997.

[RFC1928]     Leech, M., Ganis, M., Lee, Y., Kuris, R.,
                 Koblas, D., Jones, L., "SOCKS Protocol Version 5",
                 RFC 1928, March 1996.

[EXTORPORT]   Kadianakis, G., Mathewson, N., "Extended ORPort and
                 TransportControlPort", Tor Proposal 196, March 2012.

[RFC3986]     Berners-Lee, T., Fielding, R., Masinter, L., "Uniform
                 Resource Identifier (URI): Generic Syntax", RFC 3986,
                 January 2005.

[RFC1929]     Leech, M., "Username/Password Authentication for
                 SOCKS V5", RFC 1929, March 1996.
