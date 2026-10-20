import { createHash } from "node:crypto";
import type { Cookies } from "@mod/cookies";
import type { HttpRequest } from "@mod/http";
import { type Clock, type Random, sameSecret, Unavailable } from "@mod/kernel";
import { z } from "zod";
import type { RoundTripStore, StoredRoundTrip } from "./store.ts";

/** What a caller carries through a round trip: any JSON value, read back by the caller. */
export type Carried = z.infer<ReturnType<typeof z.json>>;

/** What a begun round trip gives the caller for the upstream's authorization URL, and the cookie to set. */
export interface Begun {
	readonly state: string;
	readonly nonce: string;
	readonly challenge: string;
	readonly challengeMethod: "S256";
	readonly cookie: string;
}

/** A round trip taken by its callback, or none: nothing was spent. */
export type Taken =
	| {
			readonly kind: "taken";
			readonly carried: Carried;
			readonly verifier: string;
			readonly nonce: string;
			readonly startedAt: number;
			/** The cookie cleared, for every answer from here on. */
			readonly cleared: readonly string[];
	  }
	| { readonly kind: "none" };

/** One round trip to an upstream, from its start to its callback, taken once. */
export interface RoundTrips {
	begin(at: {
		readonly name: string;
		readonly carried: Carried;
		readonly lifetimeMs: number;
		readonly crossSite?: boolean;
	}): Promise<Begun>;
	take(request: HttpRequest, name: string, state: string | undefined): Promise<Taken>;
}

const shape = z.strictObject({
	format: z.literal(1),
	name: z.string(),
	state: z.string(),
	nonce: z.string(),
	verifier: z.string(),
	startedAt: z.number(),
	carried: z.json(),
	crossSite: z.literal(true).optional(),
	taken: z.literal(true).optional(),
});
type Kept = z.infer<typeof shape>;

const toStored = (record: Kept) => record as unknown as StoredRoundTrip;
/** What a kept record holds, checked on every read; nothing for a format or shape this does not know. */
const fromStored = (stored: StoredRoundTrip | undefined) => {
	const read = shape.safeParse(stored);
	return read.success ? read.data : undefined;
};

const s256 = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

/** Round trips kept in `store`, their cookies written and read by `cookies`. */
export function roundTripsOver(parts: {
	readonly store: RoundTripStore;
	readonly cookies: Cookies;
	readonly random: Random;
	readonly clock: Clock;
}): RoundTrips {
	const secret = () => Buffer.from(parts.random.bytes(32)).toString("base64url");
	const cookieOf = (name: string, value: string, seconds: number, crossSite?: true) =>
		parts.cookies.write(name, value, seconds, crossSite ? { crossSite } : {});
	return {
		begin: async ({ name, carried, lifetimeMs, crossSite }) => {
			const id = secret();
			const record: Kept = {
				format: 1,
				name,
				state: secret(),
				nonce: secret(),
				verifier: secret(),
				startedAt: parts.clock.now(),
				carried,
				...(crossSite ? { crossSite: true } : {}),
			};
			// A record already under a fresh 256-bit id is a store that cannot keep it apart.
			const saved = await parts.store.save(id, toStored(record), lifetimeMs);
			if (saved !== "created") throw new Unavailable("upstream-round-trip");
			return {
				state: record.state,
				nonce: record.nonce,
				challenge: s256(record.verifier),
				challengeMethod: "S256",
				// Under a second would be a Max-Age of 0, which clears it.
				cookie: cookieOf(name, id, Math.max(1, Math.ceil(lifetimeMs / 1000)), record.crossSite),
			};
		},
		take: async (request, name, state) => {
			const kept = parts.cookies.lookup(request, name);
			if (kept.kind !== "found" || state === undefined) return { kind: "none" };
			const taking = await parts.store.update(kept.value, (stored) => {
				const current = fromStored(stored);
				if (!current || current.name !== name || !sameSecret(current.state, state))
					return undefined;
				return { value: toStored({ ...current, taken: true }) };
			});
			const before = fromStored(taking?.before);
			// Untaken before this change, and taken after it: this callback took it, and only once.
			if (!before || before.taken || fromStored(taking?.after)?.taken !== true)
				return { kind: "none" };
			return {
				kind: "taken",
				carried: before.carried,
				verifier: before.verifier,
				nonce: before.nonce,
				startedAt: before.startedAt,
				cleared: [cookieOf(name, "", 0, before.crossSite)],
			};
		},
	};
}
