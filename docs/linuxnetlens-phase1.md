# LinuxNetLens — Phase 1 MVP

On-demand Linux network root-cause analysis for VMs and containers.
LinuxNetLens ships as a **separate top-level package** (`linuxnetlens/`)
alongside the existing NetScope package, which remains unchanged.

---

## What Phase 1 does

Given a flow (5-tuple), LinuxNetLens captures a short window of eBPF
events on the local Linux host, correlates them, and produces a
per-flow **Diagnosis** with two **independent** confidence numbers:

1. **`outcome_confidence`** — how sure we are of the four-outcome
   verdict:
   - `BLOCKED` — the local guest OS dropped this flow.
   - `NO_RESPONSE` — the flow left the guest but no reply arrived.
   - `RESET` — a TCP RST was observed.
   - `UNKNOWN` — insufficient evidence.
2. **`attribution_confidence`** — how sure we are of the winning
   `DropLocation` (FIREWALL, TCP Stack, Application/Socket, Softnet,
   NIC Driver, XDP, TC, or UNKNOWN).

Reporting the two numbers separately makes it possible to say things
like *"NO_RESPONSE (high confidence), attribution TCP (low
confidence)"* rather than falsely pinning blame on a firewall.

---

## Correctness invariants (test-enforced)

- **`BLOCKED` is never claimed** without one of:
  (a) an `nf_hook_slow` verdict of DROP or REJECT observed for the
       flow, **or**
  (b) a `kfree_skb` reason in
       `linuxnetlens.kernel_map.BLOCKED_FAMILY_REASONS`:
       `NETFILTER_DROP`, `BPF_CGROUP_EGRESS`, `IP_RPFILTER`,
       `SOCKET_FILTER`.
- Retransmits + no reply is **`NO_RESPONSE`**, never `BLOCKED`.
- `xdp_exception` is not conflated with `XDP_DROP`; and even a real
  `SKB_DROP_REASON_XDP` alone does not classify as `BLOCKED` in Phase 1.
- No nftables rule handle or chain name is ever reported unless the
  kernel probe (`nft_do_chain`) actually captured it.
- PID/process attribution never relies on `sock_alloc` alone.
  Every `SocketOwner` carries a `Certainty` of `OBSERVED`,
  `INFERRED`, or `ASSUMED` and the CLI/reports surface that.

---

## Package layout

```
linuxnetlens/
    __init__.py             — public API + __version__
    models.py               — Outcome, DropLocation, Hypothesis, Diagnosis
    events.py               — Typed event model + JSON (de)serialization
    flow.py                 — FlowKey / FlowFilter / FlowTable
    socket_registry.py      — 4-source PID join + `ss` reconciliation
    verdict_ledger.py       — Per-flow event timeline
    kernel_map.py           — SKB_DROP_REASON_* → (DropLocation, weight)
    outcome.py              — Four-outcome classifier
    attribution.py          — RootCauseAttributor + AttributionResult
    report.py               — Terminal report formatter
    cli.py                  — `linuxnetlens {diagnose,info}` CLI
    backends/
        __init__.py         — detect_backend / list_backends
        base.py             — BpfBackend ABC
        simulated.py        — JSON-replay backend (Windows/CI/demos)
        bpftrace.py         — Linux bpftrace subprocess backend
    programs/
        skb_drop_reasons.bt
        tcp_lifecycle.bt
        tcp_reset.bt
        nf_verdict.bt
        socket_owner.bt
```

Fixtures live under `examples/linuxnetlens/`:
`blocked_nft.json`, `no_response.json`, `reset_remote.json`,
`unknown_empty.json`.

---

## Backends

| Backend    | Available on | Requires                        |
|------------|--------------|---------------------------------|
| simulated  | Windows/Linux/CI | nothing (JSON replay)       |
| bpftrace   | Linux        | `bpftrace` binary in `$PATH`, `CAP_BPF`+`CAP_PERFMON` (or root), kernel >= 5.17 for full drop-reason coverage (RHEL 8/9 backport partial) |

`detect_backend()` picks bpftrace on Linux if available, otherwise
falls back to `SimulatedBackend`. `--replay` always forces the
simulated backend.

---

## CLI usage

```bash
# Diagnose a specific flow for 10 s
sudo linuxnetlens diagnose --flow tcp:10.0.0.4:*->10.0.0.9:443

# Replay a captured fixture (no eBPF required)
linuxnetlens diagnose --replay examples/linuxnetlens/blocked_nft.json

# Broad capture (guard-rail: requires explicit opt-in)
sudo linuxnetlens diagnose --confirm-broad --duration 5

# JSON output
linuxnetlens diagnose --replay ... --json

# Backend detection
linuxnetlens info
```

Broad captures are refused by default so the tool cannot be pointed
at a busy host without the operator's consent.

---

## Test coverage summary

The Phase 1 tests (all under `tests/test_lnl_*.py`) cover:

- Typed event roundtrip + refusal to accept a `rule_handle` field on
  `NfVerdictEvent`.
- Flow canonicalization (IPv4-mapped IPv6), reversed lookups, filter
  parsing, LRU eviction, and bpftrace-guard emission.
- Socket registry: OBSERVED / INFERRED / ASSUMED certainty precedence
  and merge behaviour.
- Verdict ledger: partitioning of blocked-family vs. other SKB drops,
  retransmit counting, reset direction capture.
- Kernel map: `BLOCKED_FAMILY_REASONS` disjoint from ambiguous
  reasons; every entry references a valid `DropLocation`.
- **OutcomeClassifier**: the critical negative test that retransmits
  + no verdict + no reset must not be `BLOCKED`; positive tests for
  netfilter and blocked-family reasons; RESET precedence over
  NO_RESPONSE; BLOCKED precedence over RESET.
- Attribution end-to-end from all four fixtures; refusal to attribute
  FIREWALL without evidence; dual confidence numbers.
- Backends: simulated availability everywhere; bpftrace unavailable
  on non-posix; broad-capture guard-rail on CLI.
- CLI: exit codes, JSON output, and layout keywords.

Test count: **83 passed** (28 pre-existing NetScope + 55 new
LinuxNetLens Phase 1).

---

## Known Phase 1 limitations

- The five `.bt` programs are skeletons that establish the JSON
  event contract and flow-guard templating. Full 5-tuple extraction
  from `sk_buff` in bpftrace requires host-specific offsets and is
  best treated as a Phase 1.5 hardening task on a live Linux target.
- `SKB_DROP_REASON_XDP` is recorded but the attributor deprioritises
  it: XDP-caused guest-side drops need Phase 2 corroboration
  (bpf_prog_query / bpftool net show).
- No live streaming CLI command yet — Phase 1 is capture-then-attribute.
- No HTML or Prometheus report writers yet; only terminal and JSON.
- `ss` reconciliation is ASSUMED-only. It never overrides an
  OBSERVED PID from an LSM/kprobe.

---

## What Phase 2 will add

- BCC / libbpf CO-RE backend option
- Live streaming attribution + a monitor subcommand
- Optional LSM-based socket_bind / socket_connect probes for OBSERVED
  PID/netns without kprobe symbols
- Cgroup / netns-scoped filtering
- XDP program enumeration (`bpftool net show`) as corroborating
  evidence for XDP attribution
- HTML report writer
- Kubernetes-aware annotation (pod / container correlation)
