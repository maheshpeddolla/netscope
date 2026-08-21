"""
Kernel SKB drop-reason interpretation for LinuxNetLens.

The kernel exposes an ``enum skb_drop_reason`` on the
``skb:kfree_skb`` tracepoint (Linux >= 5.17; partially backported on
RHEL 8/9). Each reason maps to a coarse LinuxNetLens DropLocation
with a base weight (higher = more specific, more trustworthy).

The set is intentionally conservative: unknown reasons return
(UNKNOWN, small floor weight) so they are surfaced as evidence
rather than silently discarded, but they cannot win an attribution.

Constants:

- ``BLOCKED_FAMILY_REASONS`` — the exact skb reasons that suffice to
  classify a flow as BLOCKED by the guest OS (used by the
  OutcomeClassifier). No reason outside this set may be used to make
  that claim.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple

from linuxnetlens.models import DropLocation


# ----------------------------------------------------------------------
# Blocked-family: the ONLY skb reasons that justify an outcome of
# BLOCKED without an accompanying nf_hook_slow verdict.
# ----------------------------------------------------------------------

BLOCKED_FAMILY_REASONS: FrozenSet[str] = frozenset(
    {
        "SKB_DROP_REASON_NETFILTER_DROP",
        "SKB_DROP_REASON_BPF_CGROUP_EGRESS",
        "SKB_DROP_REASON_IP_RPFILTER",
        "SKB_DROP_REASON_SOCKET_FILTER",
    }
)


# ----------------------------------------------------------------------
# SKB_DROP_REASON_* -> (DropLocation, weight)
# ----------------------------------------------------------------------

DROP_REASON_MAP: Dict[str, Tuple[DropLocation, int]] = {

    # --- Netfilter / firewall ------------------------------------------
    "SKB_DROP_REASON_NETFILTER_DROP":       (DropLocation.FIREWALL, 70),
    "SKB_DROP_REASON_BPF_CGROUP_EGRESS":    (DropLocation.FIREWALL, 55),
    "SKB_DROP_REASON_IP_RPFILTER":          (DropLocation.FIREWALL, 55),
    "SKB_DROP_REASON_SOCKET_FILTER":        (DropLocation.FIREWALL, 40),

    # --- TCP stack / socket --------------------------------------------
    "SKB_DROP_REASON_TCP_CSUM":             (DropLocation.TCP, 55),
    "SKB_DROP_REASON_TCP_FLAGS":            (DropLocation.TCP, 45),
    "SKB_DROP_REASON_TCP_ZEROWINDOW":       (DropLocation.TCP, 40),
    "SKB_DROP_REASON_TCP_OLD_DATA":         (DropLocation.TCP, 35),
    "SKB_DROP_REASON_TCP_OVERWINDOW":       (DropLocation.TCP, 40),
    "SKB_DROP_REASON_TCP_OFOMERGE":         (DropLocation.TCP, 30),
    "SKB_DROP_REASON_TCP_RFC7323_PAWS":     (DropLocation.TCP, 35),
    "SKB_DROP_REASON_TCP_INVALID_SEQUENCE": (DropLocation.TCP, 40),
    "SKB_DROP_REASON_TCP_RESET":            (DropLocation.TCP, 35),
    "SKB_DROP_REASON_TCP_LISTEN_OVERFLOW":  (DropLocation.APPLICATION, 55),
    "SKB_DROP_REASON_TCP_MINTTL":           (DropLocation.TCP, 30),
    "SKB_DROP_REASON_TCP_MD5NOTFOUND":      (DropLocation.TCP, 50),
    "SKB_DROP_REASON_TCP_MD5UNEXPECTED":    (DropLocation.TCP, 50),
    "SKB_DROP_REASON_TCP_MD5FAILURE":       (DropLocation.TCP, 50),

    "SKB_DROP_REASON_NO_SOCKET":            (DropLocation.APPLICATION, 55),
    "SKB_DROP_REASON_SOCKET_RCVBUFF":       (DropLocation.APPLICATION, 55),
    "SKB_DROP_REASON_UNIX_SKIP_OOB":        (DropLocation.APPLICATION, 25),
    "SKB_DROP_REASON_PROTO_MEM":            (DropLocation.APPLICATION, 40),

    # --- Softnet / backlog / memory ------------------------------------
    "SKB_DROP_REASON_CPU_BACKLOG":          (DropLocation.SOFTNET, 60),
    "SKB_DROP_REASON_NOMEM":                (DropLocation.SOFTNET, 45),
    "SKB_DROP_REASON_SOCKET_BACKLOG":       (DropLocation.SOFTNET, 40),

    # --- IP / L3 -------------------------------------------------------
    "SKB_DROP_REASON_IP_CSUM":              (DropLocation.NIC_DRIVER, 45),
    "SKB_DROP_REASON_IP_INHDR":             (DropLocation.NIC_DRIVER, 45),
    "SKB_DROP_REASON_IP_NOPROTO":           (DropLocation.TCP, 30),
    "SKB_DROP_REASON_IP_INADDRERRORS":      (DropLocation.TCP, 30),
    "SKB_DROP_REASON_IP_OUTNOROUTES":       (DropLocation.TCP, 40),

    # --- Neighbour / ARP -----------------------------------------------
    "SKB_DROP_REASON_NEIGH_FAILED":         (DropLocation.NIC_DRIVER, 40),
    "SKB_DROP_REASON_NEIGH_QUEUEFULL":      (DropLocation.NIC_DRIVER, 40),
    "SKB_DROP_REASON_NEIGH_DEAD":           (DropLocation.NIC_DRIVER, 45),

    # --- NIC layer -----------------------------------------------------
    "SKB_DROP_REASON_PKT_TOO_SMALL":        (DropLocation.NIC_DRIVER, 30),
    "SKB_DROP_REASON_PKT_TOO_BIG":          (DropLocation.NIC_DRIVER, 30),
    "SKB_DROP_REASON_DEV_READY":            (DropLocation.NIC_DRIVER, 40),
    "SKB_DROP_REASON_DEV_HDR":              (DropLocation.NIC_DRIVER, 40),

    # --- XDP / TC ------------------------------------------------------
    # Recorded but Phase 1 attributor deprioritises picking these as
    # winners so we cannot overclaim XDP/TC without corroboration.
    "SKB_DROP_REASON_XDP":                  (DropLocation.XDP, 60),
    "SKB_DROP_REASON_QDISC_DROP":           (DropLocation.TC, 55),
    "SKB_DROP_REASON_TC_INGRESS":           (DropLocation.TC, 50),
    "SKB_DROP_REASON_TC_EGRESS":            (DropLocation.TC, 50),

    # --- Miscellaneous / unspecified -----------------------------------
    "SKB_DROP_REASON_NOT_SPECIFIED":        (DropLocation.UNKNOWN, 10),
    "SKB_DROP_REASON_OTHERHOST":            (DropLocation.NIC_DRIVER, 20),
}


def attribute_drop_reason(reason: str) -> Tuple[DropLocation, int]:
    """
    Map a raw SKB_DROP_REASON_* string to (DropLocation, weight).

    Unknown reasons return (UNKNOWN, 10) so they still register as
    evidence without becoming winners.
    """

    if not reason:
        return (DropLocation.UNKNOWN, 5)

    normalized = reason.strip().upper()

    if not normalized.startswith("SKB_DROP_REASON_"):
        normalized = "SKB_DROP_REASON_" + normalized

    return DROP_REASON_MAP.get(normalized, (DropLocation.UNKNOWN, 10))
