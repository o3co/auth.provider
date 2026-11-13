import type { Verdict } from "./revocation.ts";

/** How often a warning of one reason is logged at most, with how many it stands for. */
const everyMs = 60_000;

/**
 * Logs a peer's revocation that is not good, by its reason and a count alone (never a host, a URL or
 * a parser's words): `outbound.revocation_revoked`, `outbound.revocation_unconfirmed`, each reason at
 * most once a minute, counting those since. Unconfirmed is a debug line where the operator accepts it.
 */
export function noticesOver(
	log: {
		warn(event: string, fields: Readonly<Record<string, string | number>>): void;
		debug(event: string, fields: Readonly<Record<string, string | number>>): void;
	},
	now: () => number,
	acceptUnconfirmed: boolean,
) {
	const pending = new Map<string, { at: number; count: number }>();
	return (verdict: Verdict) => {
		if (verdict.kind === "good") return;
		const key = verdict.kind === "revoked" ? "revoked" : verdict.reason;
		const seen = pending.get(key) ?? { at: -Infinity, count: 0 };
		seen.count++;
		pending.set(key, seen);
		if (now() - seen.at < everyMs) return;
		const count = seen.count;
		seen.at = now();
		seen.count = 0;
		if (verdict.kind === "revoked") log.warn("outbound.revocation_revoked", { count });
		else {
			const level = acceptUnconfirmed ? "debug" : "warn";
			log[level]("outbound.revocation_unconfirmed", { reason: verdict.reason, count });
		}
	};
}
