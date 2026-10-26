import type { Ceiling } from "@mod/client-allowance";
import type { Policy } from "@mod/external-jwt";
import { algorithms } from "../contract.ts";
import type { IssuerEntry } from "../issuers/issuers.ts";

/** The section's lifetime and clock skew, in seconds, which an entry narrows. */
export interface Limits {
	readonly "max-assertion-lifetime": number;
	readonly "clock-skew": number;
}

/** The widest clock skew a setting takes (5m): a spent assertion is kept past it, whatever is set. */
const widestSkewMs = 300_000;
/** Kept longer than any assertion is taken by this much, so clock differences never let one back. */
const usedAllowanceMs = 60_000;

/** An issuer's clock allowance (ms): its own, or the section's. */
export const skewOf = (entry: IssuerEntry, limits: Limits) =>
	(entry["clock-skew"] ?? limits["clock-skew"]) * 1000;

/** How an issuer's assertions are verified: its keys' algorithms, its lifetime and skew, this server's audiences. */
export const verifierPolicy = (
	entry: IssuerEntry,
	limits: Limits,
	audiences: readonly string[],
): Policy => ({
	algorithms:
		"keys" in entry ? [...new Set(entry.keys.map((k) => k.alg))] : (entry.algorithms ?? algorithms),
	skewMs: skewOf(entry, limits),
	maxLifetimeMs: (entry["max-assertion-lifetime"] ?? limits["max-assertion-lifetime"]) * 1000,
	expect: { aud: [...audiences] },
});

/** Until when a spent assertion stays used (epoch ms): set by no setting, so a change of one never lets it back. */
export const keepUntilOf = (expiresAt: number) => expiresAt + widestSkewMs + usedAllowanceMs;

/** The ceilings an issuer holds its tokens to: its own, where it writes one. */
export function ceilingsOf(entry: IssuerEntry): readonly Ceiling[] {
	if (!entry.ceiling) return [];
	const { scopes, audiences } = entry.ceiling;
	return [{ ...(scopes ? { scopes } : {}), ...(audiences ? { audiences } : {}) }];
}
