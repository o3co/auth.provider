import type { Random } from "@mod/kernel";
import type { AccessGrant, Actor } from "./contract.ts";

/** An access token's lifetime where the section does not set one. */
export const defaultLifetimeSeconds = 3600;

/** The longest lifetime an access token is issued with, a day. */
const maxLifetimeSeconds = 86_400;
/** How far ahead of the clock a token's iat is taken, for clocks that differ between hosts. */
const iatAheadMs = 60_000;

export function lifetimeOf(asked: number | undefined, configured: number): number {
	if (asked === undefined) return configured;
	if (Number.isInteger(asked) && asked >= 1 && asked <= maxLifetimeSeconds) return asked;
	throw new RangeError("tokens: a lifetime asked is 1 to 86400 whole seconds");
}

/** iat and exp in epoch seconds: the lifetime from now, capped at `notAfter` (epoch ms), never before iat. */
export function expiryOf(nowMs: number, lifetimeSeconds: number, notAfter?: number) {
	const iat = Math.floor(nowMs / 1000);
	const cap = notAfter === undefined ? Number.POSITIVE_INFINITY : Math.floor(notAfter / 1000);
	return { iat, exp: Math.max(iat, Math.min(iat + lifetimeSeconds, cap)) };
}

/** How deep an actor chain may go: past token-exchange's deepest (10), so every one issued is read. */
const actorDepth = 16;

/** Whether a chain, each link to the next by `next`, is within the actor depth, counted before it is read recursively. */
export function chainWithin(start: unknown, next: (link: object) => unknown): boolean {
	let depth = 0;
	for (let at = start; at !== undefined; at = next(at as object)) {
		if (at === null || typeof at !== "object" || ++depth > actorDepth) return false;
	}
	return true;
}

/**
 * A grant's actor chain as plain links, each of the caller's read once, within the actor depth;
 * none for none. Throws TypeError, the caller's mistake, on a chain deeper or holding what is no actor.
 */
export function actorSnapshot(actor: unknown): Actor | undefined {
	const subjects: unknown[] = [];
	for (let at = actor; at !== undefined; ) {
		if (at === null || typeof at !== "object" || subjects.length === actorDepth) {
			throw new TypeError("tokens: an actor chain is over 16 deep, or holds what is no actor");
		}
		const { subject, actor: next } = at as Actor;
		subjects.push(subject);
		at = next;
	}
	return subjects.reduceRight<Actor | undefined>(
		(inner, subject) => ({ subject, ...(inner ? { actor: inner } : {}) }) as Actor,
		undefined,
	);
}

/** Whether a token's iat and exp are as tokens issues them: exp not before iat, iat at most a minute ahead, a day at most between them. */
export function issuedWithin(iat: number, exp: number, nowMs: number): boolean {
	return exp >= iat && iat * 1000 <= nowMs + iatAheadMs && exp - iat <= maxLifetimeSeconds;
}

/** A token's id: 16 random bytes in base64url. */
export const tokenId = (random: Random) => Buffer.from(random.bytes(16)).toString("base64url");

/** A grant as a token keeps it: no empty amr, no time it does not know, the time to the second and never after `iat`. */
export function keptGrant(grant: AccessGrant, iat: number): AccessGrant {
	const { amr, authenticatedAtUnknown, acr, ...known } = grant;
	const { authenticatedAt: stated, ...rest } = known;
	const authenticatedAt = authenticatedAtUnknown ? undefined : stated;
	if (acr === "" || (authenticatedAt !== undefined && !Number.isFinite(authenticatedAt))) {
		throw new RangeError("tokens: an acr is a name, and an authentication time a number");
	}
	return Object.freeze({
		...rest,
		...(amr && amr.length > 0 ? { amr } : {}),
		...(authenticatedAt === undefined
			? {}
			: { authenticatedAt: Math.min(Math.floor(authenticatedAt / 1000), iat) * 1000 }),
		...(acr === undefined ? {} : { acr }),
	});
}
