# Looking Glass Current Status

This document summarizes what is currently implemented in this fork. It is
derived from `docs/FEATURE_ROADMAP.md` and intentionally omits future plans.

## Completed (This Fork)

- ✅ Multi-datacenter support (datacenter-scoped routers)
- ✅ File download speed tests (1MB, 10MB, 100MB)
- ✅ DNS lookup (forward + reverse)
- ✅ WHOIS lookup (IP + ASN)
- ✅ Delegation system for speed tests, DNS, and WHOIS
- ✅ Interface statistics (justlinux, disabled by default)
- ✅ System information (justlinux, disabled by default)
- ✅ New router types: TNSR, justlinux, speedtest, VyOS update
- ✅ Security hardening for input validation and command injection mitigation

## Implemented (Limited Router Types)

- ✅ MTR (My Traceroute) - implemented for `justlinux`, `speedtest`, and `tnsr` only
  - Other router types do not currently expose MTR

## Upstream Baseline (Still Present)

- ✅ Ping (IPv4/IPv6)
- ✅ Traceroute (IPv4/IPv6)
- ✅ BGP Route Lookup
- ✅ AS Path Regex Search
- ✅ AS Number Lookup
