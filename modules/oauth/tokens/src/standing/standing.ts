import type { AccessGrant } from "../contract.ts";

/** A grant's standing time as its claim writes it: whole seconds, floored and never after `iat`; none without one. */
export function standingOf(grant: AccessGrant, iat: number): number | undefined {
	const { standingAt } = grant;
	if (standingAt === undefined) return undefined;
	if (!Number.isFinite(standingAt)) throw new RangeError("tokens: a standing time is a number");
	return Math.min(Math.floor(standingAt / 1000), iat);
}

/** A token's standing in whole seconds, its claim else its `iat`; none for a claim tokens never writes, one after `iat`. */
export const standingRead = (claim: number | undefined, iat: number): number | undefined =>
	claim === undefined ? iat : claim <= iat ? claim : undefined;
