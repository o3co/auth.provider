import { Unavailable } from "@mod/kernel";
import { isCanonical } from "@mod/webauthn";
import { z } from "zod";
import type { ChallengeStore, RegistrationChallengeStore, StoredChallenge } from "../store.ts";

/**
 * What a challenge was made for: a subject's registration, or an assertion by anyone, redeemed by who
 * asked (`by`) with the same id (kept as its digest, `requester`).
 */
export type Purpose =
	| { readonly kind: "registration"; readonly subject: string }
	| { readonly kind: "assertion"; readonly by: string; readonly requester: string };

/** A purpose as taken: an assertion kept as format 1, as 0.18 opened it, names no asker. */
export type Opened =
	| Purpose
	| { readonly kind: "assertion"; readonly by?: undefined; readonly requester: string };

const storedChallenge = (value: object) => value as unknown as StoredChallenge;
const taken = storedChallenge({ v: 2, taken: true });
// Format 2 is written; format 1, the one before, is still read.
const openedShape = z.union([
	z.object({
		v: z.literal(2),
		kind: z.literal("assertion"),
		by: z.string(),
		requester: z.string(),
		at: z.number(),
	}),
	z.object({
		v: z.literal(1),
		kind: z.literal("assertion"),
		requester: z.string(),
		at: z.number(),
	}),
	z.object({
		v: z.literal(2),
		kind: z.literal("registration"),
		subject: z.string(),
		at: z.number(),
	}),
	z.object({
		v: z.literal(1),
		kind: z.literal("registration"),
		subject: z.string(),
		at: z.number(),
	}),
]);

const isChallenge = (text: string) =>
	isCanonical(text, 32) && Buffer.from(text, "base64url").length === 32;

/**
 * Challenges of 32 bytes, each taken once, with when they were made: a registration's in
 * `registrations` where composed, for its subject, every other in `store`.
 */
export function keptChallenges(
	store: ChallengeStore,
	now: () => number,
	lifetimeMs: number,
	registrations?: RegistrationChallengeStore,
) {
	return {
		open: async (challenge: string, purpose: Purpose): Promise<void> => {
			const record = storedChallenge({ v: 2, ...purpose, at: now() });
			const opened =
				registrations && purpose.kind === "registration"
					? await registrations.open(challenge, record, lifetimeMs, purpose.subject)
					: await store.open(challenge, record, lifetimeMs);
			// 32 random bytes meeting another challenge cannot be told from a broken place; an erased
			// subject's registration has no place to be kept.
			if (opened !== "created") throw new Unavailable("passkeys");
		},
		/** The purpose and time of a challenge made for `kind` and not yet taken; none for any other. */
		take: async (
			challenge: string,
			kind: Purpose["kind"],
		): Promise<(Opened & { readonly at: number }) | undefined> => {
			if (!isChallenge(challenge)) return undefined;
			// A registration's where it is kept, else in the challenge store, where 0.19 opened it; a taken
			// mark is an answer. TODO(0.22): the registration challenge store's alone.
			const own =
				registrations && kind === "registration"
					? await registrations.update(challenge, () => ({ value: taken }))
					: undefined;
			const held = own ?? (await store.take(challenge, taken));
			const parsed = openedShape.safeParse(held?.before);
			// Found where this kind is looked up but made for another: taken there all the same, so it is
			// answered once, and none to this caller.
			if (!parsed.success || parsed.data.kind !== kind) return undefined;
			// Ended on kernel's clock, as a late write gives it the store's full lifetime again.
			if (now() - parsed.data.at >= lifetimeMs) return undefined;
			const { v: _version, ...opened } = parsed.data;
			return opened;
		},
	};
}

export type KeptChallenges = ReturnType<typeof keptChallenges>;
