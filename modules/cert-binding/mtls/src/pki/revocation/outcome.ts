import type { Fetched } from "../contract.ts";

export type Failed = { readonly kind: "refused" | "outage"; readonly reason: string };

/** Only an outage is left to the caller's policy; anything else not good refuses. */
export type Status = { readonly kind: "good" } | { readonly kind: "revoked" } | Failed;
/** A status as a source says it, a revocation telling whether it is on hold. */
export type Said =
	| { readonly kind: "good" }
	| { readonly kind: "revoked"; readonly held: boolean }
	| Failed;

export const good = { kind: "good" } as const;
export const isFailed = (x: { readonly kind: string }): x is Failed =>
	x.kind === "refused" || x.kind === "outage";
export const refused = (reason: string): Failed => ({ kind: "refused", reason });
export const outage = (reason: string): Failed => ({ kind: "outage", reason });
/** The failure to report: a refusal outweighs an outage; otherwise the first found stands. */
export const worse = (a: Failed | undefined, b: Failed) =>
	!a || (a.kind === "outage" && b.kind === "refused") ? b : a;
export const failedOf = (fetched: Exclude<Fetched, { kind: "material" }>) =>
	fetched.kind === "refused" ? refused("source refused") : outage("unreachable");
export const limited = outage("fetch limit");

/** One check's fetches, within its limit; none past it, and nothing remembered for those. */
export type Fetch = (url: string, body?: Uint8Array) => Promise<Fetched | undefined>;
