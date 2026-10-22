import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import { type Credential, credentialLimits, credentialOf, isCanonical } from "@mod/webauthn";
import { z } from "zod";
import type { ChallengeStore, PasskeyStore, StoredChallenge, StoredPasskey } from "./store.ts";

const { handleBytes, idBytes } = credentialLimits;

export interface Holder {
	readonly handle: string;
	readonly credentials: readonly string[];
}

export interface Passkey {
	readonly subject: string;
	readonly credential: Omit<Credential, "userHandle">;
}

const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");
const subjectKey = (subject: string) => `s-${hashOf(subject)}`;
const credentialKey = (id: string) => `c-${hashOf(id)}`;
const broken = () => new Unavailable("passkeys");

const canonical = (max: number) => z.string().refine((text) => isCanonical(text, max));
const holderShape = z.object({
	v: z.literal(1),
	handle: canonical(handleBytes),
	credentials: z.array(z.string()),
});
const passkeyShape = z.object({
	v: z.literal(1),
	subject: z.string(),
	publicKey: canonical(4096),
	signCount: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
	backupEligible: z.boolean(),
	backedUp: z.boolean(),
	transports: z.array(z.string()).optional(),
});

/** A kept holder in the one shape written, or unavailable: a broken record decides nothing. */
function holderOf(record: StoredPasskey): Holder {
	const parsed = holderShape.safeParse(record);
	if (!parsed.success) throw broken();
	return { handle: parsed.data.handle, credentials: parsed.data.credentials };
}

function passkeyOf(id: string, record: StoredPasskey): Passkey {
	const parsed = passkeyShape.safeParse(record);
	if (!parsed.success) throw broken();
	const { subject, transports, publicKey, signCount, backupEligible, backedUp } = parsed.data;
	return {
		subject,
		credential: {
			id,
			publicKey,
			signCount,
			backupEligible,
			backedUp,
			...(transports ? { transports } : {}),
		},
	};
}

const stored = (value: object) => value as unknown as StoredPasskey;

/** Passkeys and their holders, written only in canonical form and read only in the shape written. */
export function keptPasskeys(store: PasskeyStore) {
	const holder = async (subject: string) => {
		const record = await store.subjects.read(subjectKey(subject));
		return record && holderOf(record);
	};
	/** Takes over a credential no holder lists (a failed registration's, or one between its writes), while it holds what was read. */
	const takeUnlisted = async (id: string, record: StoredPasskey): Promise<boolean> => {
		const key = credentialKey(id);
		const seen = await store.credentials.read(key);
		if (!seen) throw broken();
		const owner = await holder(passkeyOf(id, seen).subject);
		if (owner?.credentials.includes(id)) return false;
		const same = (r: StoredPasskey) => JSON.stringify(r) === JSON.stringify(seen);
		const taken = await store.credentials.update(key, (current) =>
			same(current) ? { value: record } : undefined,
		);
		return taken !== undefined && same(taken.before);
	};
	return {
		holder,
		/** The subject's handle; `fresh` becomes it when the subject has none yet. */
		handleFor: async (subject: string, fresh: string): Promise<string> => {
			if (!isCanonical(fresh, handleBytes)) throw new Error("a handle must be canonical");
			const first = stored({ v: 1, handle: fresh, credentials: [] });
			await store.subjects.save(subjectKey(subject), first, "endless");
			const kept = await holder(subject);
			if (!kept) throw broken();
			return kept.handle;
		},
		passkey: async (id: string): Promise<Passkey | undefined> => {
			if (!isCanonical(id, idBytes)) return undefined;
			const record = await store.credentials.read(credentialKey(id));
			return record && passkeyOf(id, record);
		},
		/** Keeps a new passkey for the subject, whose handle it was made for; an id its holder lists is a conflict. */
		register: async (
			subject: string,
			credential: Credential,
			max: number,
			nickname?: string,
		): Promise<"registered" | "conflict" | "full" | "malformed"> => {
			// Only what reads back: a record no read can take would make every later use unavailable.
			if (!credentialOf(credential)) return "malformed";
			const { id, userHandle, ...rest } = credential;
			const kept = await holder(subject);
			if (kept?.handle !== userHandle) return "malformed";
			if (kept.credentials.length >= max) return "full";
			const record = stored({ v: 1, subject, ...rest, ...(nickname ? { nickname } : {}) });
			const key = credentialKey(id);
			if ((await store.credentials.save(key, record, "endless")) === "exists") {
				if (!(await takeUnlisted(id, record))) return "conflict";
			}
			const listed = await store.subjects.update(subjectKey(subject), (current) => {
				const { credentials } = holderOf(current);
				if (credentials.includes(id) || credentials.length >= max) return undefined;
				return { value: stored({ ...current, credentials: [...credentials, id] }) };
			});
			if (!listed) throw broken();
			return holderOf(listed.after).credentials.includes(id) ? "registered" : "full";
		},
		/** Moves the count on from the one judged; another change first is a lost race. */
		count: async (judged: Credential, next: Credential): Promise<"counted" | "raced"> => {
			const changed = await store.credentials.update(credentialKey(judged.id), (current) => {
				if (passkeyOf(judged.id, current).credential.signCount !== judged.signCount)
					return undefined;
				return {
					value: stored({ ...current, signCount: next.signCount, backedUp: next.backedUp }),
				};
			});
			// Written only over the count judged, so the count before tells whether this one wrote.
			const before = changed && passkeyOf(judged.id, changed.before).credential.signCount;
			return before === judged.signCount ? "counted" : "raced";
		},
	};
}

export type KeptPasskeys = ReturnType<typeof keptPasskeys>;

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
			if ((await store.open(challenge, record, lifetimeMs)) === "exists") throw broken();
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
