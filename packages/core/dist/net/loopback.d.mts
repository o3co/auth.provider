/**
 * Whether `hostname` names an address that never leaves the machine.
 *
 * Accepted forms:
 *
 *   - `localhost` (exact — `URL.hostname` has already lowercased a URL host,
 *     and a raw config value spelled `LOCALHOST` is a typo, not an intent);
 *   - IPv6 loopback both as `URL.hostname` reports it (`[::1]`, always
 *     bracketed) and as a raw hostname outside a URL (`::1`) — both denote
 *     the same address, and accepting only one form is exactly how the
 *     pre-#364 copies drifted;
 *   - the whole `127.0.0.0/8` block as a dotted quad — `127.0.0.53`
 *     (systemd-resolved) and friends are as local as `127.0.0.1`.
 *
 * IPv4 shorthand (`127.1`) and full-form IPv6 (`0:0:0:0:0:0:0:1`) are
 * deliberately NOT accepted: `URL.hostname` normalizes both before they get
 * here, so a value still in that shape did not come from a URL — and
 * accepting textual variants open-endedly is how a comparison becomes a
 * parser.
 */
export declare function isLoopbackHostname(hostname: string): boolean;
//# sourceMappingURL=loopback.d.mts.map