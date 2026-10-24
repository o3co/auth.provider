import { Unavailable } from "@mod/kernel";
import { isCanonical } from "@mod/webauthn";
import { z } from "zod";
import type { ChallengeStore, StoredChallenge } from "../store.ts";

/** What a challenge was made for: a subject's registration, or an assertion by anyone, redeemed by its requester (kept as a digest). */
export type Purpose =
	| { readonly kind: "registration"; readonly subject: string }
	| { readonly kind: "assertion"; readonly requester: string };

const storedChallenge = (value: object) => value as unknown as StoredChallenge;
const taken = storedChallenge({ v: 1, taken: true });
const openedShape = z.discriminatedUnion("kind", [
	z.object({
		v: z.literal(1),
		kind: z.literal("assertion"),
		requester: z.string(),
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

/** Challenges of 32 bytes, each taken once, with when they were made. */
export function keptChallenges(store: ChallengeStore, now: () => number, lifetimeMs: number) {
	return {
		open: async (challenge: string, purpose: Purpose): Promise<void> => {
			const record = storedChallenge({ v: 1, ...purpose, at: now() });
			// 32 random bytes meeting another challenge cannot be told from a broken place.
			if ((await store.open(challenge, record, lifetimeMs)) === "exists")
				throw new Unavailable("passkeys");
		},
		/** The purpose and time of a challenge made and not yet taken; none for any other. */
		take: async (challenge: string): Promise<(Purpose & { readonly at: number }) | undefined> => {
			if (!isChallenge(challenge)) return undefined;
			const parsed = openedShape.safeParse((await store.take(challenge, taken))?.before);
			// Ended on kernel's clock, as a late write gives it the store's full lifetime again.
			if (!parsed.success || now() - parsed.data.at >= lifetimeMs) return undefined;
			const { v: _version, ...opened } = parsed.data;
			return opened;
		},
	};
}

export type KeptChallenges = ReturnType<typeof keptChallenges>;
