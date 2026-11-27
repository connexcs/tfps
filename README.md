# TFPS

**Telephony Fraud Prevention System** for SIP networks. One static binary, no cloud, no
policy configuration.

TFPS **detects and prevents SIP fraud by banning attacker addresses in the kernel.** Think
of it as a **faster `fail2ban`**: it reads SIP straight off the wire instead of tailing and
parsing log files, so it reacts in packets rather than log-flush intervals, and it catches
attacks the logs never record. As a side effect the banned traffic vanishes from your
`sngrep`.

> **About this fork.** This is ConnexCS's fork of [sippulse/tfps](https://github.com/sippulse/tfps).
> The original is built for a single server and keeps its attack surface as small as possible.
> We run hundreds of servers, so this fork adds fleet-scale integrations:
>
> - an optional JSON-over-HTTP API and Prometheus metrics endpoint
> - optional HTTP webhooks on events
> - optional HEP ingestion, so a proxy such as OpenSIPS can pass in WebRTC and TLS traffic
>   that TFPS cannot read off the wire
>
> Each of these is **off by default**. With them off, the fork behaves like upstream. Each one
> you turn on adds attack surface that a single-server install does not need, so if you run
> one server, use the upstream project.
>
> We do not send these changes upstream by default, because they may not fit the original
> project's goals. Upstream is welcome to take any of them, and we will open pull requests on
> request.
>
> *AI disclosure:* plans are drafted with Claude Fable 5.2, code is written with Claude Opus 5.5,
> reviews use GitHub Copilot, and a final security audit uses Codex.

## Install

```sh
curl -fsSL https://tfps.co/install.sh | sh
```

Linux x86_64, kernel 5.15 or newer with BTF, systemd. That is the whole install; it asks for
`sudo` if needed, and running it again upgrades. Pinning a version, air-gapped hosts, building
from source and uninstalling are in [INSTALL.md](INSTALL.md).

Two layers, and the first is the product:

- **Prevention** (default, on): drops SIP scanning, brute-force and known-bad sources —
  the `fail2ban` job, done faster and without log parsing. Most installs only ever want this.
- **Behavioural detection** (`--behavioural`, off, **highly experimental**): goes where no
  other system does — the **compromised downstream PBX**, where the attacker already holds
  valid credentials and every perimeter signal is clean. It catches IRSF by anomaly. It is a
  research-grade layer, not a guarantee.

> **Not a guarantee. Use at your own risk.** TFPS sees SIP on the wire only. It cannot detect
> every fraud type (SIP over TLS/TCP content that is not mirrored to it over HEP, IPv6, billing or insider fraud, social
> engineering, low-and-slow mimicry, fraud that never touches the network). Behavioural
> detection is experimental and report-only by default. Source-level XDP blocking is opt-in
> with `--enforce-behavioural`, and the forged SIP `603` is still missing. Validate it on your
> own traffic; it is not a substitute for a security audit or financial controls. See the
> full Disclaimer below.

- **Static musl binaries** — `tfps` ≈ 4.3 MB, `tfps_ctl` ≈ 2.3 MB. No glibc dependency;
  they run on Ubuntu 24.04, Debian 12 and forward.
- **No UDP bind** — capture is `AF_PACKET`, so your softswitch keeps its own socket on 5060
  and never notices. (The optional HEP listener binds its own port, `127.0.0.1:9061` by
  default, and only when you enable it.)
- **Kernel-level drop** — condemned sources vanish from `sngrep`, `tcpdump` and `tshark`.

> ⭐ **If TFPS keeps your `sngrep` clean or your bill honest, please star the repo** — it is
> open source and non-commercial, and a star is how it reaches the next operator who needs it.

---

## The garbage disappears from sngrep

This is what the product delivers, and it works because of one specific ordering inside the
Linux kernel:

```
NIC → driver → XDP ← TFPS drops here
                 ↓
            sk_buff → ptype_all ← libpcap hooks here (sngrep, tcpdump, tshark)
                        ↓
                    netfilter ← iptables and nftables act here
```

A packet dropped at **XDP never reaches the libpcap tap**. That is why `nftables` would not
work for this purpose: its drop happens later, and your capture would still be polluted.

**Verified in production**: with ~2,000 sources blocked (APIBAN + perimeter), a `tcpdump`
filtered to a sample of them captured a fraction of the packets a control window did. It is
not hermetic — the occasional packet slips through — but the reduction is drastic, and the
noisiest scanners disappear from the capture entirely.

---

## Two layers, one binary

| | **Prevention** (default) | **Behavioural detection** (`--behavioural`) |
|---|---|---|
| what it does | bans scanning, injection, brute-force, known-bad IPs | catches the compromised PBX — IRSF by anomaly |
| compared to | a faster `fail2ban`, no log parsing | goes where fail2ban structurally cannot |
| maturity | production | **highly experimental** |
| needs learning? | no — effective from minute one | yes — 30-day learning window before it acts |
| the signal | user-agent, URI shape, failed auth, APIBAN | four-arm sequential detector (see below) |
| default | **on** | **off** |

```sh
tfps                 # prevention only — the product
tfps --behavioural   # add the experimental behavioural layer
```

The banner always says which of the two you are running, so it is never ambiguous.

### Why faster than fail2ban

`fail2ban` tails a log file and matches a regex, so it is bounded by how often the softswitch
flushes logs and by whether the event is logged at all — Asterisk's security channel ships
off, PJSIP does not log below 5 requests in 5 s. TFPS reads the SIP on the wire: a rejected
credential or a scanner user-agent is seen **as the packet arrives**, and the ban is written
to the kernel immediately. It also sees what the logs never record, and it needs no logging
configured on the softswitch at all.

---

## Status — v0.3.1

| working | not yet |
|---|---|
| `AF_PACKET` capture, no port bind | — |
| XDP enforcement of perimeter blocks (native/generic) | SIP over TCP/TLS on the wire (detection) |
| perimeter: user-agent, URI injection, failed auth | IPv6 |
| SIP over TLS, WebSocket and TCP mirrored over HEP (opt-in) | HEP over TCP, compressed HEP |
| APIBAN, background-synced and persisted | call-duration signal via `BYE` |
| `ignoreip`, with the host's own addresses always exempt | day-31 activation confirmation |
| four-arm behavioural detector, self-calibrating | |
| source-level behavioural enforcement (`--enforce-behavioural`) | forged SIP `603` |
| SQLite persistence and control tool | |

**The perimeter enforces today; the behavioural layer detects and reports by default.**
During the 30-day learning window it prints `WOULD BLOCK` lines and blocks nothing. After
that it prints `BLOCK (report-only, not enforced)` lines with the evidence. With
`--enforce-behavioural` (or `"enforce_behavioural": true`) the same verdict is written into
XDP for `block_ttl` and logged as `BLOCKED ... reason=behavioural`; the forged SIP `603
Decline` of `SPEC.md` §8 is still missing.
A registered peer is exempt from the third-party APIBAN feed, but no longer from the
perimeter's or behavioural layer's own active evidence (injection, auth failure, registration scanning, auth
volume); only a successful REGISTER grants known-good status, for 24 hours. Read the
`WOULD BLOCK`/`BLOCK` lines and the `tfps_ctl stats` calibration to judge how the detector
fits your traffic before wiring enforcement on.

---

## The perimeter — the default product

Every packet on a watched port is checked, cheapest first. A match **condemns the source**:
its next packets die at XDP and vanish from the capture.

- **Known scanner user-agents** — 18 built-in signatures (`friendly`, `sipcli`, `sipvicious`,
  `pplsip`, `sipsorcery`, `Nmap NSE`…). Weak as *detection* — a competent attacker forges a
  legitimate UA — but most scanning traffic uses a default one, so as a *volume filter* it
  earns its place. A missing `User-Agent` is **not** noise.
- **URI injection** — 11 built-in patterns (`'`, `%27`, `--`, `?=?`, `union`, `select`, and
  `;` inside the user part), matched against the `user@host` of the Request-URI, `From` and
  `To` only — never the display name, so an Irish surname is not mistaken for SQL injection.
  Higher confidence than a user-agent: no real phone puts a single quote in a `From` header.
- **Scanner identity** — a known scanner domain or tool name in the `From`/`To`/`Contact`/
  Request-URI, matched on **every method** (scanners probe with `OPTIONS` as much as
  `INVITE`). This catches the self-identifying research scanners the user-agent list misses —
  Censys announces itself as `censysinspect@censys.io`, and there are Shodan, LeakIX and the
  rest, plus tool/service domains like `sip5060.net`. A real caller is never `@censys.io`.
  Extend the built-in list with `scanners` in the config.
- **Registration scanning** — a source that probes **many different extensions** with
  `REGISTER` and **completes none** (no `2xx`). This catches extension enumeration and the
  no-credential probing the failed-auth rule can't see: the attacker spreads a few tries per
  extension across the dial plan, so no single extension crosses the brute-force threshold —
  but one source touching several distinct extensions with zero successful registrations is
  a scan. The count is of *distinct extensions*, not raw attempts, and that is deliberately
  the safe design: a real phone registers its own one extension (a multi-line device its own
  few) however many times it retransmits or re-registers, and whether or not its responses
  are captured, so it never climbs; and any single successful registration exempts the source
  outright. The threshold sits well above any plausible legitimate device, so a NAT or
  gateway behind one IP is never caught — only a source spraying the dial plan is.
- **Failed authentication** — see below.
- **APIBAN** — the collaborative bad-IP list, if a key is configured.

The perimeter does **not** exist to catch fraud. It exists to keep noise out of the
behavioural baseline: if scanning fed a source's baseline, the detector would learn that
bursts to strange destinations are normal there, and poison itself.

### Failed authentication, and what does not count

**A bare `401` means nothing.** Digest is a two-step flow: every legitimate `REGISTER` gets
a `401` with a nonce and is resent with `Authorization`. Counting challenges would block
every customer.

What counts is a request that **carried a credential and was answered `401`/`407` anyway**:

```
REGISTER (no Authorization)  →  401 + nonce     the normal handshake, ignored
REGISTER (Authorization)     →  200 OK          accepted — the count is cleared
REGISTER (Authorization)     →  401 again       a rejected password. This is the signal.
```

Five rejections in ten minutes condemn the source — `fail2ban`'s `maxretry`/`findtime` for
the Asterisk jail, deliberately, but read off the wire instead of a log the softswitch may
not be writing. Requests are matched to responses by the `Via` branch (RFC 3261 §17.1.3),
falling back to `Call-ID` + `CSeq`. A retransmitted `401` counts once; an accepted credential
clears only that AOR's failures, so someone who fixes a typo is not blocked by their next
slip, while a valid account cannot reset a run against a different extension. The source of
the response must also match the request's destination. A NAT whose phones succeed is below
the registration-scan floor; a NAT with no captured responses can still look like an
enumerator, so put it in `ignoreip`.

**The backstop**: where the softswitch rejects probes *without* answering (measured on the
reference server: one outbound packet in 45 s against hundreds inbound), the failure counter
cannot rise, so a volume rule remains — 50 authenticated attempts in 60 s with no challenge
seen. When that condition is detected, TFPS **says so** on the report, because a rule that
structurally cannot fire is the `fail2ban` blindness this project exists to avoid.

---

## Behavioural detection — the experimental layer

> ⚠️ **Highly experimental.** This layer is research-grade: it addresses a case no other tool
> reaches, but it has not earned the confidence the prevention layer has. Run it in learning
> mode, read the `WOULD BLOCK` lines, and judge it on your own traffic before trusting it.

It exists for one case the prevention layer — and `fail2ban`, and reputation lists — cannot
touch: the **compromised downstream PBX**. The attacker already holds a valid credential, the
traffic arrives authenticated from the usual IP, and every perimeter signal is clean. Nothing
that keys on *reputation* or *authentication failure* sees it. TFPS keys on **behaviour**:
what a source does with those valid credentials.

Turn it on with `--behavioural`. It learns each **source IP**'s normal behaviour and flags
IRSF by anomaly.

### Enable it

```json
{
  "behavioural": true,
  "enforce_behavioural": false,
  "intl_prefixes": ["+", "00", "011", "9011"],
  "home_countries": ["BR"],
  "learn_days": 30,
  "ignoreip": ["10.0.0.0/8"]
}
```

```sh
tfps --behavioural                              # 30-day learning window, report-only
tfps --behavioural --enforce-behavioural        # block after learning
tfps --behavioural --active --enforce-behavioural # block now; do not do this on day one
```

The first **30 days are learning**: it prints `WOULD BLOCK` and blocks nothing. Each new
source also has its own **24 h / 20 international call** warm-up (`WARMING`). After that the
verdict is printed as `BLOCK (report-only, not enforced)` unless `--enforce-behavioural` (or
`"enforce_behavioural": true`) is set, in which case the source is written into XDP for
`block_ttl` and the log says `BLOCKED ... reason=behavioural`. The perimeter still enforces;
the forged SIP `603` is the remaining piece. Watch `WOULD BLOCK` lines and `tfps_ctl stats` during the
window. To disable, remove `--behavioural` or set `"behavioural": false`; learned state stays
on disk until `tfps_ctl forget`.

Use `--no-enforce-one-way` (or `"no_enforce_one_way": true`) if the one-way perimeter evidence
is exposed to spoofing: those verdicts stay report-only; behavioural detection is unchanged.

> **Prerequisite — configure your international prefixes.** The behavioural layer reasons
> only about **international** destinations, and `intl_prefixes` (global and per-peer) is how
> it tells a real outbound international call from an internal extension or an inbound call to
> an E.164 DID. Get them wrong and the wrong calls are judged. The defaults are a starting
> point, not a fit for your installation — set them, and the detector's job becomes correct.
>
> **Two companions to that setting**, both about not judging traffic that isn't outbound
> international fraud:
>
> - **`home_countries`** — your own country (or countries), as ISO labels (`+1` is `NANP`).
>   A destination that resolves to one of them is *national*, not international, even when it
>   arrives with a `+` or in E.164 — so an inbound call to your own DID is not mistaken for a
>   foreign destination. Without it, startup recommends setting it.
> - **`ignoreip` your inbound gateways** — the carriers that deliver calls *to* your internal
>   destinations should never be judged or blocked. Put their IPs in `ignoreip`; startup
>   recommends this too.

The full design and its literature are in
[`docs/anomaly-detection.md`](docs/anomaly-detection.md); in brief:

**The B-number cannot be classified.** Tested against a real libphonenumber port, classic
IRSF destinations (Latvia, Somalia, the Philippines) validate as ordinary mobile numbers,
while some genuine ranges are rejected. Neither validity nor number-type separates fraud
from legitimate traffic. Detection has to be **behavioural**.

**IRSF has a behavioural signature, in phases**, and each maps onto a solved problem:

- **Scanning** — finding a target, working out how to dial out, then finding which premium
  numbers route. The SIP search for a target belongs to the perimeter; the other two are
  first-contact discovery and are detected with a **Threshold Random Walk** (Jung et
  al., IEEE S&P 2004) — a sequential test that accumulates evidence per call and fires the
  moment it is sufficient. Three arms run: a new **dialling prefix** (`00`, `011`, `9011`,
  `+`…), a new **destination range** (the B-number with its last four digits dropped — the
  premium-rate hunt), and a **failed completion** (a call answered `4xx`/`5xx`/`6xx`, or
  never — the AT&T signature, "the call never came here"). A never-seen **country** is *not*
  a separate arm: every new country is already a new range, and country novelty was too
  fragile on its own. The seen-country set is still tracked for the report.
- **Exploitation** — hammering the route it found shows as a volume spike against the
  source's own norm, scored with **hierarchical Gamma-Poisson surprise**.

The four arms produce evidence in the same log-likelihood units, so they **add**;
enforcement fires when the total crosses a bound set by the **error rates you choose**
(α, β) — not a hand-picked threshold. Every block is one explainable sentence:
*"14 nats: 9 range-scan, 3.5 volume."* Each arm also has a hard floor (4 dialling
prefixes, 10 destination ranges, 10 failed novel ranges), and a new source is observed for
24 hours / 20 international calls before it can be blocked. Those floors are the
false-positive control; the SPRT decides once a burst is real.

**It self-calibrates.** The benign hypotheses — how often a normal source uses a new
dialling prefix or a new destination range, how often calls fail, the population's rate
distribution — are learned from the
deployment's *own* aggregate traffic during the learning window and refit at each
checkpoint. The only policy numbers are **α and β** — the tolerated false-alarm and miss
rates — never a traffic constant. They are compiled-in defaults today (`1e-4`, `1e-2`), not
yet exposed in the config file. `tfps_ctl stats` shows the learned values.

**Its one honest weakness**: a low-and-slow attacker who mimics a legitimate profile at low
volume. Which is exactly why this layer is opt-in, blocks are temporary, and the unban rate
is watched as the precision proxy.

---

## Configuration — `/etc/tfps/config.json`

**Every field is optional and the system works without the file.** What lives here is
**installation** configuration — where to look, how to read the numbers — plus optional
integrations. Never **policy** configuration, which would say what fraud is.

```json
{
  "ports": [5060, 5061],
  "intl_prefixes": ["+", "00", "011", "9011"],

  "peers": {
    "10.0.0.5":    { "intl_prefixes": ["9011", "011"] },
    "203.0.113.7": { "bare_e164": true }
  },

  "signatures": ["MyLocalScanner", "=sipsak"],
  "injection": ["xp_cmdshell"],
  "scanners": ["newscanner.example.com"],
  "ignoreip": ["10.0.0.0/8", "203.0.113.7"],
  "home_countries": ["BR"],

  "behavioural": false,
  "enforce_behavioural": false,
  "no_enforce_one_way": false,
  "apiban_key": "optional-key",

  "learn_days": 30,
  "block_ttl": 3600,
  "stats_every": 120,
  "checkpoint_every": 300,
  "iface": "eth0",
  "db": "/var/lib/tfps/tfps.db",

  "http": { "enabled": false, "listen": "127.0.0.1:9060", "allow_unban": false },
  "hooks": [],
  "hooks_poll_secs": 1,

  "hep": { "enabled": false, "listen": "127.0.0.1:9061", "allow_from": ["127.0.0.1"],
           "transports": ["tcp"], "auth_key": null }
}
```

`http` configures the optional JSON API and `hooks` the optional webhooks, both served by
`tfps_ctl serve`; the daemon ignores them. See "JSON API" and "Webhooks" below. `hep` is the
daemon's optional HEP listener; see "TLS and WebSocket via HEP".

Precedence: **command line > file > built-in default**, so you can debug in production
without editing a file. An **unknown field is an error**, not silence: an `apiban_kei`
quietly ignored would make you believe you enabled APIBAN when you did not. Malformed JSON
and an invalid peer IP become startup alarms too. (Renamed fields keep an alias, so a config
from an earlier version still loads rather than silently reverting to defaults.)

### `peers` — the dial plan per PBX

Declaring beats learning because it holds on that peer's **very first** call instead of
waiting for convergence, and the weight is large: **20.3% of destinations do not resolve to
a country** without correct prefix stripping. `bare_e164` says the PBX sends plain E.164 with
no prefix — common in wholesale; it is an explicit field because the semantics are
dangerous: with it on, `2125551234` is Morocco; with it off, a domestic US number.

### NANPA (+1) — the Caribbean is international

`+1` is not one country. The US and Canada share it with ~30 Caribbean and territory nations
— Dominica (+1-767), Grenada (+1-473), Jamaica (+1-876), Antigua (+1-268)… — and several are
**IPRN hotspots**: fraud that looks like a domestic `+1` call but routes internationally to a
premium range. TFPS breaks `+1` into all of them; only geographic US/Canada resolves to
`NANP`.

To catch it as a NANPA operator, two settings:

```json
{ "peers": { "10.0.0.5": { "bare_e164": true } }, "home_countries": ["NANP"] }
```

- **`bare_e164`** (or the `+` prefix) so a `+1XXX` number keeps its country code and resolves
  to the real country — **never a stripped `"1"` prefix**: stripping the `1` turns 1-212 into
  `212` (Morocco) and 1-767 into `767…` (Russia). TFPS warns at startup if it sees `"1"`
  configured as a prefix.
- **`home_countries: ["NANP"]`** so geographic US/Canada is national, while the Caribbean +1
  countries — separate entries — are judged as international, which is what they are.

### `signatures` and `injection` — they add, never replace

The seeds are compiled into the binary and work with no file. What you list is **added** to
the 18 built-in user-agents and 11 built-in patterns — replacing would make someone who
writes three lines silently lose the built-ins. Prefix match by default; `=text` matches
exactly. TFPS warns when no signature has matched after thousands of messages: a rule that
never fires is rotten.

### `ignoreip` — sources never enforced against

The equivalent of `fail2ban`'s field of the same name. The host's **own addresses are always
exempt** and need no entry — that is not configuration, it is read from the machine, and it
exists because a defence that can condemn its own host will eventually do so. Declared
entries add trusted carriers and management ranges. `tfps_ctl ban` applies the same list:
the host's addresses, the file's entries, and the entries the daemon persisted at its last
checkpoint (which is how a `--ignoreip` given on its command line reaches a hand ban). It
does not exempt registered peers — a hand ban is the explicit override of that heuristic.
An exempt source is still evaluated, counted and reported; only the block is withheld. Two rules keep it from becoming a policy knob: **`0.0.0.0/0` is refused** (use
`--no-enforce`, which announces itself), and every entry counts its hits, so a stale
exemption shows as cold.

### `apiban_key` — optional integration

The collaborative [APIBAN](https://apiban.org) list, fed by honeypots, on a **separate
thread**: HTTP never touches the packet path. That is exactly where the 2023 TFPS died — a
synchronous `rest_get()` per INVITE, ~26 INVITEs/s, any outage froze every call. Here the
feed is resumed from its persisted cursor, re-applied for 7 days after a restart (so the
integration never comes back protecting nothing), and honours `ignoreip`. The key is read
only from the config file (installed `0600`); it is deliberately not a command-line flag,
because argv is visible to local users and shell history.

---

## Building

```sh
cargo test                                                   # ~317 tests
cargo build --release --target x86_64-unknown-linux-musl
```

The musl target produces **static binaries with no glibc dependency** — `tfps` ≈ 4.3 MB,
`tfps_ctl` ≈ 2.3 MB — that run on Debian 12, Ubuntu 24.04 and whatever comes next. This
solved a real case: the build machine had glibc 2.39 and the server 2.36, and glibc is not
forward compatible.

SQLite is compiled in, which needs a C compiler that can target musl. If you do not have
`musl-tools`, [zig](https://ziglang.org) works and needs no root:

```sh
export CC_x86_64_unknown_linux_musl="zig cc -target x86_64-linux-musl"
export AR_x86_64_unknown_linux_musl="zig ar"
```

The XDP program is written in C (`ebpf/tfps_xdp.c`) because only the kernel side needs LLVM.
The installer compiles it against the running kernel's BTF; requires kernel **≥ 5.15** with
BTF.

---

## Installing and running

On the target machine:

```sh
curl -fsSL https://tfps.co/install.sh | sh
```

Idempotent: run it again to upgrade, and it never overwrites `/etc/tfps/config.json`. From
a checkout, `sudo ./packaging/install.sh` does the same with what you built. Every step,
the knobs and the uninstall are in [INSTALL.md](INSTALL.md).

```sh
journalctl -u tfps -f      # watch it decide, live
tfps_ctl status            # what it has learned, what is blocked
```

**It also runs with no configuration and no arguments** — `tfps` on its own uses the
built-in defaults. Capture needs `CAP_NET_RAW`; XDP needs `CAP_BPF` and `CAP_NET_ADMIN`
(and, on some kernels, `CAP_SYS_ADMIN` — verify on your target; the packaged unit explains
why).

| flag | effect |
|---|---|
| `--behavioural` | turn on the experimental behavioural layer (default: OFF, prevention only) |
| `--ports 5060,5080` | SIP ports to watch (default `5060`) |
| `--intl +,00,011,9011` | international dialling prefixes |
| `--ignoreip CIDR` | never enforce against this address/network (repeatable) |
| `--learn-days N` | days observing before the behavioural layer acts (default `30`) |
| `--active` | skip the learning period |
| `--no-enforce` | observe only, do not touch XDP |
| `--no-enforce-one-way` | report user-agent, scanner, injection, duplicate-header, registration-scan and auth-volume evidence, but do not block it (spoofable source); response-based auth failures and APIBAN still enforce |
| `--enforce-one-way` | override a config file that set `no_enforce_one_way: true` |
| `--enforce-behavioural` | enforce a behavioural `Block` by writing the source into XDP for `block_ttl` (requires `--behavioural`) |
| `--no-enforce-behavioural` | report behavioural verdicts only (default) |
| `--config PATH` | configuration (default `/etc/tfps/config.json`) |
| `--db PATH` / `--no-db` | SQLite database, or run without persistence |
| `-v` / `--debug-unparsed` | verbose; show payloads that failed to parse |

---

## Controlling it — `tfps_ctl`

The counterpart to `fail2ban-client`. With no labels, **how often you unban is the only
precision measure this system has**, so that act is one command.

```
tfps_ctl status                       what is running, what is blocked, how fresh the state is
tfps_ctl stats                        every counter: kernel drops, traffic mix, calibration
tfps_ctl banned [--why]               condemned sources, with time left and the reason
tfps_ctl unban <ip>... | --all        lift a block — takes effect on the next packet
tfps_ctl ban <ip> [--ttl N]           condemn by hand (default 3600s, 0 = no expiry)
                                      refuses this host's addresses and anything in ignoreip;
                                      exits non-zero if any address was refused or failed
tfps_ctl sources [--peer --country]   learned sources and the countries they call
tfps_ctl source <peer>                everything known about one source
tfps_ctl peers                        sources by country breadth, when last heard
tfps_ctl log [--limit N] [--ip IP]    the block audit log, newest first
tfps_ctl serve                        the optional JSON API and /metrics — see "JSON API"

  --config PATH                       configuration, read for ignoreip (default /etc/tfps/config.json)
```

```console
# tfps_ctl stats
KERNEL  (live)
  seen on SIP ports : 21486
  dropped by XDP    : 9042 (42.1% — gone before sngrep)
  condemned now     : 2140 (2140 permanent, e.g. the APIBAN feed)

CALIBRATION  (benign hypotheses learned from this deployment)
  theta0                 0.083
  theta0c                0.310
  theta0u                0.040
  prior_mean             1.90

TRAFFIC  (as of the last checkpoint, 2m ago)
  packets              1879   sip                   768
  ...
```

**Two sources of truth, never blurred.** Blocks live in the kernel map and are read and
written directly, so an unban applies immediately. Learned state lives in SQLite and is
written at checkpoint, so `status` reports **how old that snapshot is** rather than passing
stale rows off as current. Reading blocks needs `CAP_BPF` (run as root); reading learned
state needs only the database file.

---

## JSON API

An optional HTTP server for other systems — a control panel, a ticketing tool, Prometheus —
that need to know **what is blocked and why**, and optionally to lift a block. It is
`tfps_ctl serve`, a separate process from the daemon: it reads the same kernel map and
database `tfps_ctl` reads, so the API can be stopped, restarted or upgraded without touching
enforcement, and a bug in it cannot take the packet path down with it.

**Off by default.** Turn it on in `/etc/tfps/config.json`:

```json
"http": {
  "enabled": true,
  "listen": "127.0.0.1:9060",
  "allow_unban": false,
  "hosts": [],
  "allow_remote": false,
  "token_file": "/etc/tfps/api-token"
}
```

`hosts` adds `Host` names the API answers to (the listen address, and `localhost` on
loopback, need no entry). `allow_remote` must be `true` to listen on anything but loopback.
`token_file` is optional: when set, every route but `/v1/health` needs
`Authorization: Bearer <token>`, and the file must be readable by its owner only
(`install -m 600 /dev/null /etc/tfps/api-token`, then write a long random token into it).

then start the unit the installer put in place but did not enable:

```sh
systemctl enable --now tfps-api
curl -s 127.0.0.1:9060/v1/blocks
```

`tfps_ctl serve --listen ADDR --allow-unban` override the file (command line beats file).
Neither flag turns the API on by itself: `enabled` is the one switch. The `http` section is
read when the API starts, so **after editing it, `systemctl restart tfps-api`** — including
to turn the API off. Restarting `tfps` does not restart the API: the two are separate
services, so the API can be stopped or upgraded without touching enforcement.

| method | path | answers |
|---|---|---|
| GET | `/v1/health` | `{"ok":true,"version":"…"}` |
| GET | `/v1/status` | the `status --json` document |
| GET | `/v1/stats` | the `stats --json` document |
| GET | `/v1/blocks` | every blocked source with its reason and expiry: `banned --why --json` as one array |
| GET | `/v1/blocks/{ip}` | one of those, or 404 |
| GET | `/v1/log?limit=N&ip=IP` | the block audit log, newest first (`limit` 1–1000, default 50) |
| POST | `/v1/unban` | body `{"ips":["…"],"source":"…","reason":"…"}`; only with `allow_unban` |
| GET | `/metrics` | Prometheus text format |

Every document is exactly what the matching `tfps_ctl … --json` prints, and keeps its
null-not-zero rule: an unreadable database is `null`, never `0`. Errors are
`{"error":"…"}` with 400 (bad input), 401 (token missing or wrong), 403 (unban off, a
request from a web page, or a `Host` not on the list), 404, 405, 408 (request not received
within 10 s), 411, 413 (body over 64 KiB), 415 (not `application/json`), or 503 (tfps not
running, enforcement inactive, the block map or database unreadable, or another full listing
in progress). `/v1/unban` answers with one `unban --json` document per address:
**200** when every address was lifted, **422** when any was not blocked, **500** with
`{"error":…,"results":[…]}` if the kernel failed part-way. At most 256 addresses per
request; `source` defaults to `http`, and every unban lands in the same
`manual_actions-YYYYMM.jsonl` record as one from the command line.

`/metrics` reports counts and never an address. From the kernel: the XDP counters
(`tfps_xdp_seen_total`, `tfps_xdp_dropped_total`, `tfps_xdp_expired_total`), the number of
sources in the block map now (`tfps_blocked_sources`) and how many never expire
(`tfps_blocked_sources_permanent`). From the daemon's database, through counting queries:
blocks logged by reason over the last hour, day and week
(`tfps_blocks_logged{window="1h|24h|7d",reason=…}`), the APIBAN feed size
(`tfps_apiban_feed_entries`), the traffic counters as of the last checkpoint
(`tfps_traffic_total{counter=…}`) with `tfps_checkpoint_timestamp_seconds` so staleness is
visible, and the learned totals. Plus `tfps_build_info`. A scrape's cost does not grow with
the audit log, and a value that cannot be read is left out, never reported as 0.

`/v1/blocks` and `/v1/stats` start from the block map too, and ask the audit log and the
APIBAN feed only about the addresses in it.

**Which block map.** The daemon chooses its map once, at startup, and publishes the choice
in `/run/tfps/state.json`: the kernel id of its own map, or of the shared map it opened
(with the pin path, for the record; a pin replaced later does not change which map is used).
The API reads and edits exactly that map, never one it found itself, so it cannot drift to a
map the daemon is not enforcing through. The file also names the daemon's process (pid and
start time): when tfps is not running (systemd removes the file, and a file left by a crash
names a process that is gone) or enforcement is inactive, the block routes answer 503 and say
so. `/v1/status` takes the XDP attach mode and interface from the same file, and the
`tfps_xdp_*` metrics read the counters map it names; with a shared map those counters are its
owner's, and they are left out.

### Security model — read this before exposing it

- **Loopback by default.** Listening on any other address needs `"allow_remote": true`;
  without it `serve` refuses to start. With it, `serve` still logs a `WARNING` at startup.
- **`Host` is checked.** A request must name the listen address, `localhost` (on loopback)
  or a name in `hosts`; anything else gets 403. That stops a web page that rebinds its own
  name to this address (DNS rebinding) from reading the API.
- **Web pages are refused.** Any request with an `Origin` header gets 403, and the unban
  route takes only `POST` with `Content-Type: application/json`.
- **Optional bearer token** for machine-to-machine access (`token_file`). Without one,
  anyone who can reach the listen address can read every block, and lift them when
  `allow_unban` is on. On loopback that means **every local user and process on the host**.
- **Unbanning is a second switch, off by default.** Without `allow_unban`, `/v1/unban`
  answers 403 before anything touches the block map. There is no ban over HTTP.
- **No TLS.** Put a reverse proxy (Caddy, nginx) in front for anything beyond the host.
- **Strict, bounded HTTP.** Requests are parsed by `httparse`; line endings other than
  CRLF, any `Transfer-Encoding`, and a repeated `Content-Length` or `Host` are refused, so a
  proxy and this server cannot read one request two ways. Four worker threads and a short
  queue (a full one answers 503); reading a request and writing its response each have a
  10-second deadline, so a slow client cannot hold a worker; an 8 KiB request head, a 64 KiB
  body, one request per connection. Full `/v1/blocks` listings are streamed and take turns,
  which keeps a full map (65,536 entries) at about 41 MB peak.
- **Reduced privileges.** `tfps-api.service` keeps only `CAP_BPF` and `CAP_SYS_ADMIN`
  (opening the daemon's map by id), not the daemon's capture and attach capabilities, with
  further systemd hardening on top.

Behind nginx, the default `proxy_pass` sends `Host: 127.0.0.1:9060`, which is accepted
as is:

```nginx
location /tfps/ {
    auth_basic           "tfps";
    auth_basic_user_file /etc/nginx/tfps.htpasswd;
    proxy_pass           http://127.0.0.1:9060/;
}
```

Prometheus with a token:

```yaml
scrape_configs:
  - job_name: tfps
    authorization:
      credentials_file: /etc/prometheus/tfps-token
    static_configs:
      - targets: ["127.0.0.1:9060"]
```

## Webhooks

TFPS can POST a JSON document to one or more URLs when a source is **blocked**, **unblocked**,
or its block **expires**, for a control panel, a ticketing tool or a chat bridge. They are sent
by the same `tfps_ctl serve` process as the JSON API, never by the daemon, so the packet path
gains no HTTP client. Configure the URLs and enable the unit (it runs for webhooks even with the
API off):

```json
"hooks": ["https://panel.example.com/tfps/events", "http://127.0.0.1:8080/hook"],
"hooks_poll_secs": 1
```

```sh
systemctl enable --now tfps-api      # and `systemctl restart tfps-api` after editing hooks
```

Every URL receives every event:

```json
{"event":"block","ip":"203.0.113.9","ts":1795000000,"reason":"auth_failure","detail":"…","expires":1795003600,"source":"tfps","host":"sbc1"}
```

| `event` | when | `source` |
|---|---|---|
| `block` | the daemon blocks a source (a new `block_log` row), or a manual ban is recorded | `tfps`, or who banned (`reason` is `manual`, `detail` their reason) |
| `unblock` | a manual unban is recorded (`tfps_ctl unban`, `POST /v1/unban`) | who unbanned, with their `reason` |
| `expired` | a watched block's expiry time has passed | `tfps` |
| `unblock` | a watched block left the map early with no unban on record | `unknown` |

`ts` and `expires` are Unix times; `expires` is `null` for a block with no expiry and on the end
of a block. `host` is this machine's name.

**Delivery.** Each URL has its own worker and a queue of 1,000 events, so a slow or dead
endpoint delays no other. A URL's host is looked up in `/etc/hosts` first, then in DNS (A
records, or AAAA when there are none); IPv4 addresses are tried before IPv6. An event is POSTed with a 5-second timeout and retried after 1, 2 and
4 seconds; then it is dropped and counted. `/metrics` exports
`tfps_hook_deliveries_total{url_index,result="delivered|failed|queue_full"}`. Where reading
stopped is kept in `/var/lib/tfps/hooks.cursor`, saved only when every queued event has been
delivered or given up on, so a restart never skips what was written meanwhile; events still
queued when `serve` stopped are sent again after it starts (at-least-once). The first start
begins at the current end.

**Known limits.**

- **Expiry is noticed by polling** (`hooks_poll_secs`, default 1 s), because expiry happens in
  the kernel: an `expired` event is accurate to the poll interval.
- **An address that vanishes early with no unban** — the map's LRU eviction under a
  spoofed-source flood, or another program editing a shared map — is reported as `unblock` with
  `"source":"unknown"`, one poll late (so an unban whose record is still being written is not
  misreported), never silently dropped.
- **Events are told in the order they happened** within a poll: an unban followed by a new
  block of the same address ends with the `block`, and that block's expiry is still reported.
- **Expiries are not replayed across a restart** of `serve` or of the daemon: blocks that
  expired meanwhile produce no event. The first poll after either only takes a baseline.
- **APIBAN feed blocks fire no webhooks** (thousands per sync, and not this host's own
  evidence).
- Delivery is **at-least-once within the retry budget**, not guaranteed. Events are not
  signed; put the receiver behind TLS and authenticate it by network or URL secret until
  signing is added.

---

## TLS and WebSocket via HEP

TFPS cannot read SIP over TLS or secure WebSocket (WSS) on the wire: it is encrypted. The
application server that terminates it can mirror each message, decrypted, to TFPS over
**HEP3**. TFPS then judges it as it judges UDP off the wire, and blocks through the same XDP
program. Each HEP packet carries one whole SIP message, so this also covers plain SIP over
TCP, which TFPS does not reassemble on the wire. **Off by default**: with no `hep` section, no
socket is bound and nothing changes.

It is built for one deployment: **OpenSIPS terminates TLS / WSS on the same host as TFPS** and
mirrors to it over loopback. The address OpenSIPS reports is then the client's real address,
and the XDP block lands on the machine that client connects to.

```json
"ports": [5060, 5061, 443],
"hep": {
  "enabled": true,
  "listen": "127.0.0.1:9061",
  "allow_from": ["127.0.0.1"],
  "transports": ["tcp"],
  "auth_key": null
}
```

**`ports` must list the TLS and WSS ports** (here 5061 and 443), or XDP will not drop a blocked
source there. TFPS warns once for each port it sees in HEP that `ports` does not list.

### OpenSIPS

An example for OpenSIPS 3.x; module parameters change between versions, so check it against
yours:

```
socket = hep_udp:127.0.0.1:9062              # the socket HEP is sent from
loadmodule "proto_hep.so"
loadmodule "tracer.so"
modparam("proto_hep", "hep_id", "[tfps] 127.0.0.1:9061; transport=udp; version=3")
modparam("proto_hep", "homer5_on", 1)        # plain SIP payload, not the JSON form
modparam("tracer", "trace_id", "[tfps]uri=hep:tfps")

route {
    trace("tfps", "t", "sip");               # this transaction: requests and replies
    # ...
}
```

- Trace **requests and their replies**: failed-authentication detection needs the `401` /
  `407` answers.
- Send the **plain SIP payload** (`homer5_on`), not the JSON-wrapped form.
- Check that the HEP addresses are the client's and the listening socket's, in both
  directions, on TLS and WSS connections: `tfps --verbose` prints each verdict's address.

### Security model

HEP is unauthenticated: whoever can send to the listener can get an address blocked. So:

- it is **off** by default and listens on **loopback** by default; a non-loopback `listen`
  is a startup `WARNING`;
- packets from a sender not in `allow_from` are dropped and counted;
- `auth_key` makes every packet carry that shared secret (HEP chunk 14); an empty one is
  refused and the listener does not start;
- `ignoreip` and the host's own addresses shield HEP verdicts exactly as they shield wire
  verdicts. **An upstream proxy or load balancer must be in `ignoreip`.** (A registered peer
  is not shielded from the perimeter's own evidence, on the wire or over HEP; see "Status".)

**Transports.** By default only messages that arrived over **TCP** (which covers TLS, WS and
WSS) are judged. OpenSIPS's `tracer` marks TLS with IP protocol 22 and WS / WSS with 50 in the
HEP header, as stand-ins; TFPS reads 6, 22 and 50 all as TCP. OpenSIPS traces its UDP traffic too, which TFPS already sees on the wire;
judging both would count each message twice. Add `"udp"` to `transports` only when the wire
capture cannot see that UDP.

**One-way evidence.** A TCP source address cannot be forged: the handshake completed. So
`--no-enforce-one-way`, which exists because UDP sources can be, does not downgrade evidence
that arrived over HEP with TCP transport. It still applies to wire UDP and to HEP over UDP.

**Time.** Verdicts use the local receive time. A message whose HEP timestamp is more than
5 seconds old is skipped as `stale`, so a replayed backlog cannot block for behaviour that is
over.

### Counters and alarms

The periodic report has a `HEP:` line, and `tfps_ctl stats`, its `--json` form and `/metrics`
(`tfps_traffic_total{counter="hep_…"}`) carry the same counters from the daemon's checkpoint:

| counter | meaning |
|---|---|
| `hep_received` | datagrams read |
| `hep_sip` | messages handed to the engine |
| `hep_rejected_sender` | sender not in `allow_from` |
| `hep_bad_auth` | `auth_key` missing or wrong |
| `hep_malformed` | not HEP3, a length that lies, or a required chunk missing |
| `hep_skipped_udp` / `hep_skipped_tcp` | a transport not in `transports` |
| `hep_skipped_ipv6` | IPv6 (detection and enforcement are IPv4 only) |
| `hep_skipped_proto` | not SIP (RTCP, logs, …), a compressed payload, or another transport |
| `hep_stale` | captured more than 5 seconds before it arrived |
| `hep_dropped` | the queue to the packet loop (4,096 messages or 16 MiB) was full |

**Silence is an alarm, port by port.** With HEP on, if no message for a SIP port arrives for
**5 minutes** while TCP packets are seen on that port, TFPS raises an `ALARM` naming it: the
sender has stopped, or does not trace that port, and TLS / WSS there are blind again. While
HEP delivers for a port, that port's TCP does not raise the "SIP over TCP it cannot inspect"
warning. Only messages that arrived over TCP count, and only for their own port: a stream
for 443 does not cover 5061, and HEP over UDP covers no TCP.

### Limits

- **Blocking on 443 blocks everything on 443** from that source, not only SIP.
- **Shared addresses.** WebRTC clients are often behind carrier NAT; one block can affect
  several users.
- **Detection depends on the sender.** If OpenSIPS stops tracing, TFPS is blind on TLS / WSS
  again (hence the silence alarm).
- **Detection lags the application server** by the mirroring delay. That does not matter for
  blocking a source.
- **TLS / WSS terminated elsewhere** (a proxy, load balancer or CDN): TFPS on this host cannot
  block the client, and the proxy must be in `ignoreip`.
- HEP over UDP only (not TCP or TLS); HEP3 only; no compressed payloads; IPv4 only.

---

## Reading the report

```
--- mode=PREVENTION packets=330 sip=98 responses=0 keepalive=232 not_sip=0
    noise=12 (12%) injection=0 auth_att=142 auth_fail=5 auth_ok=97 auth_chal=104
    auth_volume=0 intl_ok=0 intl_fail=0 intl_unroutable=0 intl_unanswered=0
    invites=62 intl=62 unknown_country=20
    first_time=21 blocks=0 would_block=0 sources=3 ports={5060: 330}
    XDP: dropped=1840 seen=2100 expired=3 in_map=7 blocked_by_us=7
```

| field | meaning |
|---|---|
| `mode` | PREVENTION, or (behavioural) LEARNING / ACTIVE |
| `keepalive` | NAT CRLF pings (RFC 5626) — on a residential 5060, most packets |
| `not_sip` | unclassified. **Should be ~0**; high means something is not understood |
| `noise (%)` | how much the perimeter removed — the number behind a clean sngrep |
| `auth_fail` / `auth_ok` / `auth_chal` | rejected credentials, accepted, challenges seen |
| `auth_volume` | sources condemned by the volume backstop |
| `intl_ok` / `intl_fail` | international calls observed to complete / fail (the completion arm's fuel) |
| `intl_unroutable` | of `intl_fail`, answered `403` or no-such-number (`404`/`484`/`604`…) — the discovery signature |
| `intl_unanswered` | busy / no answer / cancelled — a person was rung, not counted as a failure |
| `unknown_country` | international by shape, no recognisable country — prefix padding |
| `first_time` | first-time-country events; feeds the learned benign rate |
| `blocks` / `would_block` | behavioural verdicts (active / during learning) |
| `sources` | distinct source IPs under watch |
| `XDP: …` | what the kernel side actually did; `blocked_by_us` is what **this** process condemned |

Silence is an alarm, not normality: TFPS complains when it stops seeing traffic, when there
is SIP on IPv6/TCP it cannot inspect, when no signature has matched in thousands of messages,
and when credentials are presented with no challenge ever seen.

---

## Persistence

**SQLite. One file. No server, no daemon, no credential, no port.** The working set lives in
memory; only the boot load and the periodic checkpoint touch disk. State splits by
durability: **perimeter** state dies with the process and rebuilds from traffic in minutes
(consistent with fail-open by not pinning the eBPF program); **behavioural** state and the
APIBAN list survive on disk, the latter because it is consumed through a forward-only cursor
and cannot rebuild itself. The database is created `0600` and the state directory `0700`
when the daemon creates them: it holds customer IPs, countries called and block history, not
just counters.

---

## What it does not do

Documented, not engineered away — a limitation stated plainly beats one that fails quietly.

| not handled | why |
|---|---|
| **SIP over TLS / WSS on the wire** | encrypted payload. Mirror it from the application server over HEP to have it judged — see "TLS and WebSocket via HEP" |
| **SIP over TCP — detection on the wire** | L7 reassembly is not implemented; content is not parsed off the wire. HEP covers it, one whole message per packet. **Enforcement covers TCP** on the ports you list: a condemned source is dropped in XDP on those ports too, so add 5061 (and 443 for WSS) |
| **IPv6** | the capture takes `ETH_P_IP` only; counted and warned about |
| **IPv4 fragments** | not reassembled; any fragment (MF or offset) is counted and never judged. The softswitch may still reassemble the real message |
| **802.1Q/QinQ tagged SIP** | XDP checks for EtherType 0x0800; run the tap on an untagged interface, or add tag handling before relying on enforcement there |
| **spoofed source IP** | UDP source addresses are forgeable. Deploy BCP38/BCP84 or uRPF; otherwise one spoofed packet can trip a one-way block against another address. The block map is also a 65,536-entry LRU that a spoofed-source flood can churn. `--no-enforce-one-way` (or `no_enforce_one_way: true`) keeps those verdicts report-only |
| **a broad international profile** | anomaly saturates by construction — a peer already calling 200 countries has no burst left |
| **the first 30 days** | the behavioural layer's learning window, by design and announced |
| **a low-and-slow mimic** | the residual gap no on-wire method closes — hence opt-in, TTL'd, unbannable |
| **TLS on the JSON API** | it listens on loopback with an optional bearer token; TLS for anything wider is a reverse proxy's job — see "JSON API" |
| **forged SIP `603`** | source-level XDP blocking is available with `--enforce-behavioural`; the SIP-level reject is still missing |

---

## Disclaimer

**TFPS cannot catch every possible type of fraud.** It is one layer that sees SIP on the
wire. It does not see billing, CRM, provisioning, identity, social engineering, insider
fraud, or traffic it cannot parse (SIP over TLS or TCP content not mirrored to it over HEP,
IPv6). A determined
low-and-slow attacker can mimic a legitimate profile. Behavioural detection is experimental
and report-only by default (source-level XDP blocking is opt-in); every verdict can be
wrong.

Use it at your own risk. Validate it on your own traffic, keep the perimeter and the learning
window, and do not treat it as a substitute for a security audit, fraud controls, or your
carrier/billing reconciliation. The software is provided **AS IS**, under the Apache-2.0
licence, without warranty of any kind.

---

## Documentation

- [`docs/anomaly-detection.md`](docs/anomaly-detection.md) — the behavioural detector: the
  research, why the constraints rule out most methods, and the four-arm design
- [`DETECTION.md`](DETECTION.md) — how a packet is examined, test by test, in code order
- [`SPEC.md`](SPEC.md) — the architecture and the decisions (§6 superseded by the doc above)
- [`CONTEXT.md`](CONTEXT.md) — the vocabulary, normative for code and documentation

## Star the project

TFPS is open source, non-commercial, and built for its own use — there is nothing to sell.
If it earns its place on your box, a **GitHub star** is the whole thank-you, and it is what
helps another operator find it.

## License

Apache-2.0.
