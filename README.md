# BearSSL for sysl

TLS 1.2 at both ends, and the cryptography under it, bound to [BearSSL](https://bearssl.org) 0.6,
vendored unchanged. BearSSL never calls `malloc`, and neither does this binding: every context, buffer,
key and certificate store is storage inside the sysl values that own it. It is the org's TLS for boards,
where [`sysl-lang/openssl`](https://github.com/sysl-lang/openssl) will not fit.

*An independent sysl package for BearSSL. It is not affiliated with or endorsed by BearSSL's authors or trademark holders.*

```hocon
dependencies {
  bearssl { git = "github.com/sysl-lang/bearssl", version = "0.1.3" }
}
```

The module is `sh.sysl.bearssl`. The package needs sysl 0.6.0.

## A TLS client over a socket the program owns

The binding never sees a socket. A connection is BearSSL's engine and its I/O buffer, and four calls
move bytes across it: `outgoing` takes ciphertext to write to the peer, `incoming` hands over ciphertext
that arrived, and `send` and `receive` carry plaintext once the handshake is done. The same shape as
`sysl-lang/openssl`'s memory BIOs, so one binding serves a blocking socket, an event loop or a board's
own network stack.

```sysl
import sh.sysl.bearssl.{BUFSIZE_BIDI, Client, Connection, TrustAnchors, client, trust_anchors}

var anchors: TrustAnchors[4, 4096] = trust_anchors()
anchors.add_pem(ca_pem.bytes)?

var tls: Client[BUFSIZE_BIDI] = client()
tls.init(&anchors)                 // 1. zeroes the context and points it at the anchors
tls.seed(entropy)?                 // 2. at least 32 bytes from a real source: required
tls.start("example.com")?          // 3. the name the certificate must carry

var buf: [4096]u8 = [0; 4096]
loop
    loop                           // drain BEFORE reading, every time
        val n = tls.outgoing(buf[..])
        if n == 0 then break
        sock.send_all(buf[0..<n])?
    if tls.ready()? then break
    val got = sock.recv(buf[..])?
    var at = 0usize
    while at < got
        at += tls.incoming(buf[at..<got])
```

`send`, `receive` (`Data(n)`, `Wants` or `Closed`) and `close` work the same way, with `outgoing`
drained after each. **Drain before reading**: the engine produces bytes to send from reading as well as
from writing, and a loop that blocks on the wire while bytes sit in `outgoing` waits forever.

**A context must stay where it is from `init` on**, and so must the `TrustAnchors` or `Identity` it was
set up over: BearSSL keeps pointers into all of them. On a board they are module storage. `Client`, `Server`,
`TrustAnchors`, `Identity` and `PemReader` are `@pinned`, so sysl refuses a copy or a move.

A server is the same with `Server[IO]`, `Identity[BYTES]` (a certificate chain and its private key,
from PEM or DER, EC or RSA) and `start()` with no name. `BUFSIZE_BIDI` (about 33 KB) carries both
directions at once; `BUFSIZE_MONO` (about 16 KB) is half-duplex, for a board with little RAM.

## The entropy rule

The package compiles BearSSL with `BR_USE_URANDOM=0` and `BR_USE_GETENTROPY=0`: BearSSL takes no
randomness from the machine, because a board has none to give, and a stack that found `/dev/urandom` on
the host and nothing on the board would pass every test here and fail on the hardware. **A program must
call `seed` on every context**, with at least 32 bytes from a real source (the RP2350's TRNG, an STM32's
RNG, the host's `getentropy`). A context never seeded is refused by BearSSL itself (`NO_RANDOM`) when it
starts; one seeded with fewer than 32 bytes is refused by the binding (`SEED_TOO_SHORT`), since BearSSL
would accept a single byte.

A board has no clock either: `set_time(unix_seconds)` gives the validator its time, and a client that
never sets one refuses every certificate with `X509_TIME_UNKNOWN` there. On a host BearSSL reads the
clock itself.

## What is bound

| | |
|---|---|
| TLS 1.2 | `Client[IO]`, `Server[IO]`: `init`, `seed`, `suites`, `set_time` (client), `start`; through `Connection`: `outgoing`, `incoming`, `wants_input`, `ready`, `send`, `receive`, `close`, `last_error`, `suite`, `version` |
| suites | every TLS 1.2 suite BearSSL's `init_full` enables; constants for the six ECDHE AEAD ones (ECDSA and RSA, each with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305) |
| certificates | `TrustAnchors[N, BYTES]` (`add_pem`, `add_der`), `Identity[BYTES]` (`add_pem`, `add_certificate`, `set_key`), `certificate_public_key` |
| PEM | `PemReader`: `next`, `read`, `skip`; `private_key`, `private_key_pem` (PKCS#8, RFC 5915 EC, PKCS#1 RSA) |
| hashes | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512: `digest`, `Digest.update`/`finish`, `hash_of` |
| MAC and KDF | HMAC (`hmac`, streaming `mac`), HKDF (`hkdf`) |
| AEAD | AES-GCM (128, 192, 256; any IV length), ChaCha20-Poly1305: `*_seal` and `*_open`, in place; a failed open wipes the data |
| EC | P-256, P-384, P-521: `ec_private_key`, `generate_ec_key`, `public_key`, ECDSA `sign` (raw, deterministic per RFC 6979), `sign_der`, `verify`, `verify_der` |
| RSA | PKCS#1 v1.5 `sign` and `verify`, keys up to 4096 bits; `public_key` derived from a private key |
| random | `Random` (HMAC_DRBG over SHA-256): `random(seed)`, `fill`, `reseed` |

Every error is an `Error` holding BearSSL's own number (`X509_EXPIRED` is 54, `X509_NOT_TRUSTED` 62, a
received alert `RECV_FATAL_ALERT` plus the alert's number) or one of the binding's from 1001 up;
`message()` is a static string, so reporting one never allocates.

**Deliberately absent**, each an addition when something needs it: TLS 1.0 and 1.1 (BearSSL has them;
the binding sets 1.2 as both floor and ceiling), session resumption and caches, client certificates,
ALPN, renegotiation, CBC and CCM suites, static ECDH and RSA key exchange, X25519 as a bare function,
RSA-OAEP and PSS, RSA key generation, AES-CCM and EAX, SHAKE and MD5, the AES-NI and POWER8 back ends
(the portable constant-time code is what a microcontroller runs). TLS 1.3 and Ed25519 are not in BearSSL.

## Tests

`sysl test .` runs 56 tests. Two oracles decide them, neither of which is BearSSL.

**The standards' own vectors**, byte for byte: FIPS 180-2's SHA examples ("abc", the 448- and 896-bit
messages, a million "a") and CAVP's empty message for all five SHA widths; RFC 4231 test cases 1, 2, 3
and 6 for HMAC-SHA-224 to -512 and RFC 2202 for HMAC-SHA-1; RFC 5869 test cases 1, 3 and 4 for HKDF; the
GCM specification's test cases 1 to 6, 13, 14 and 16 (AES-128 and -256, IVs of 8, 12 and 60 bytes);
RFC 8439 §2.8.2 for ChaCha20-Poly1305; RFC 6979 A.2.5 and A.2.6 for ECDSA over P-256 with SHA-256 and
P-384 with SHA-384 (public key and both messages' `r` and `s`). Each family was proved able to fail: one
byte of its expected value changed, and its test went red.

**An independent implementation, OpenSSL 3** (Homebrew's, else the system's LibreSSL):

- RSA PKCS#1 v1.5 signatures by `openssl dgst -sign` over the same key, which BearSSL must reproduce byte
  for byte and verify; an ECDSA signature by OpenSSL (its own random nonce) that BearSSL must verify;
  the public keys `openssl x509 -text` and `openssl rsa -modulus` print.
- **TLS over real TCP sockets** (`sysl.net`), with certificates `openssl req` makes in each test. The
  BearSSL client against `openssl s_server -rev`: ECDHE-ECDSA (P-256) with ChaCha20-Poly1305 and
  AES-128-GCM, ECDHE-RSA (2048) with ChaCha20-Poly1305, AES-256-GCM and AES-128-GCM, a line sent and its
  reversal read back; refused with `X509_NOT_TRUSTED` under the wrong anchor and `X509_EXPIRED` for an
  expired certificate. `openssl s_client -verify_return_error` against the BearSSL server: ECDHE-ECDSA
  with AES-256-GCM and ChaCha20-Poly1305, ECDHE-RSA with AES-256-GCM, a line echoed and s_client exiting
  cleanly; and s_client refusing the server's certificate under the wrong CA, which the server hears
  as `RECV_FATAL_ALERT + 48` (unknown_ca). Every host process is started by recorded PID and killed.

The same engine against itself in memory covers the rest: a clean close at both ends, a record changed
in flight (`BAD_MAC`), a certificate for another name (`X509_BAD_SERVER_NAME`), validation times in
2025, 2030 and 2200, no common suite (`RECV_FATAL_ALERT + 40` at the client, `SEND_FATAL_ALERT + 40`
at the server), the seed refusals, a server with no certificate or key, and half-duplex buffers.

**Mutations**, each run and each red: entropy never injected; `outgoing` copying one byte short of what
it acknowledges; the trust anchors not handed to the validator; application records reported taken
and dropped; SHA-256's vtable swapped for SHA-224's; SHA-256's PKCS#1 prefix swapped for SHA-224's;
ChaCha20-Poly1305 sealing with the decrypt flag; the 32-byte seed floor lowered to one byte.

**AddressSanitizer**: `SYSL_EXTRA_CFLAGS="-fsanitize=address -g" sysl test .` passes 54/54. The test
binary links `__asan_memcpy` and the report hooks, and BearSSL's own functions
(`br_pem_decoder_push`) and the shim carry the shadow-memory checks.

## Bare metal

BearSSL needs no allocator and no operating system, and the binding asks for neither. The package
builds for boards with `sysl-lang/cstd` as its C library (`cstd { ..., if = "!libc" }`: where the
machine has a libc the dependency is dropped). The suite builds the package with `sysl build-c` for
`thumbv7em-freestanding` and `riscv32-freestanding` and checks with `nm` that the archive defines
BearSSL's entry points and cstd's `memcpy`, `memset` and `strlen`. It needs sysl 0.6.0 or later.

## Vendored

`c/bearssl/src` and `c/bearssl/inc` are BearSSL 0.6's own directories, unchanged, with its
`LICENSE.txt`, from the tarball whose SHA-256 is
`6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14`. `sysl.hocon`'s `c` block compiles
`src/**/*.c` (277 files) with `BR_USE_URANDOM=0` and `BR_USE_GETENTROPY=0`; an upgrade is a copy of the
next release over the tree. Vendoring means upstream fixes do not arrive on their own: watch
bearssl.org and re-vendor.

Licensing: BearSSL is MIT; the rest of this package is ISC. Both texts are in `LICENSE`, BearSSL's
verbatim.
