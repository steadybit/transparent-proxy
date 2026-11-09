Follow-up from the review of steadybit/transparent-proxy#12 (card 26649, per-request percentage on HTTPS).

With an interception CA, a rule with an HTTP status now decrypts every TLS connection whose SNI matches, whatever the percentage. Before, only the faulted share was decrypted. Two side effects were left out of that PR.

1. Non-HTTP TLS to a matched hostname fails on every connection

If the same hostname also serves another protocol over TLS on a captured port (IMAPS, LDAPS, Kafka, a database), every connection to it is served as HTTP and fails, even at 0%.

Client without ALPN: gets HTTP/1.1 400 Bad Request.

Client with a non-HTTP ALPN (e.g. imap): handshake fails with no application protocol.

Both are counted as tls_intercept_rejected, with the warning "is the CA trusted by the target?", which points the operator at a truststore that is fine.

Only happens when that port is captured: an empty port list (all ports), or a non-HTTP protocol on 443.

Already done in #12: the README documents it and recommends --intercept-ports 443.

To do: when the ClientHello offers ALPN values but neither h2 nor http/1.1, splice the connection through instead of decrypting it. Needs the ClientHello parser (parseSNI in internal/proxy) to also read ALPN. Clients that send no ALPN can't be told apart without decrypting; that case stays documented only.

2. Idle pre-opened HTTPS connections are closed after 10s and counted as CA rejections

On HTTP/1.1, the 10s ReadHeaderTimeout in internal/tlsinject applies to the first request. A connection opened ahead of time (pool warm-up, browser preconnect) that sends nothing for 10s is closed. A connection that ends without any request is recorded as a post-handshake rejection, so it raises tls_intercept_rejected.

To do:

Raise or rethink the first-request timeout for intercepted connections.

Tell an idle close apart from a TLS 1.3 client that rejected the certificate (both look like "handshake done, then no request"). E.g. a TLS alert such as bad_certificate/unknown_ca on read vs. a plain EOF/close_notify.

Low impact: services rarely pre-open connections to their dependencies.