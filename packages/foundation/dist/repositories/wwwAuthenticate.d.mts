/**
 * Whether a `WWW-Authenticate` value carries a `Bearer` challenge (RFC 6750
 * §3). Quoted strings are blanked first, so `realm="… Bearer …"` is not one;
 * several header lines arrive joined by `, `, which this reads as the
 * challenge list it is. A malformed line — a quoted string never closed —
 * hides whatever follows it, including a challenge on a later line: the
 * answer is then read as it would be without one, never the other way.
 */
export declare function hasBearerChallenge(value: string | null): boolean;
//# sourceMappingURL=wwwAuthenticate.d.mts.map