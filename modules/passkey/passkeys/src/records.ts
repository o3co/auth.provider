import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import { type Credential, credentialLimits, credentialOf, isCanonical } from "@mod/webauthn";
import { z } from "zod";
import type { RegisteredPasskey } from "./contract.ts";
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
	nickname: z.string().optional(),
	at: z.number().optional(),
});
/**
 * A passkey written and not yet admitted: no read takes it as one. Its version is not the live
 * one's, so a host reading only that one finds it broken, never a passkey. `token` names the write.
 */
const pendingShape = passkeyShape
	.omit({ v: true })
	.extend({ v: z.literal(2), pending: z.literal(true), token: z.string() });
/** What a removed passkey leaves: its holder, and that it was removed; no key, count or name. */
const removedShape = z.object({ v: z.literal(1), subject: z.string(), removed: z.literal(true) });

/** A kept holder in the one shape written, or unavailable: a broken record decides nothing. */
function holderOf(record: StoredPasskey): Holder {
	const parsed = holderShape.safeParse(record);
	if (!parsed.success) throw broken();
	return { handle: parsed.data.handle, credentials: parsed.data.credentials };
}

/** A kept passkey, or the subject a removed one was held by; unavailable for any other shape. */
function keptOf(record: StoredPasskey) {
	const live = passkeyShape.safeParse(record);
	if (live.success) return { kind: "passkey" as const, ...live.data };
	const pending = pendingShape.safeParse(record);
	if (pending.success) return { kind: "pending" as const, ...pending.data };
	const removed = removedShape.safeParse(record);
	if (removed.success) return { kind: "removed" as const, subject: removed.data.subject };
	throw broken();
}

/** A kept passkey; none for one removed, or pending. */
function passkeyOf(id: string, record: StoredPasskey): Passkey | undefined {
	const kept = keptOf(record);
	if (kept.kind !== "passkey") return undefined;
	const { subject, transports, publicKey, signCount, backupEligible, backedUp } = kept;
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

/**
 * Passkeys and their holders, written only in canonical form and read only in the shape written;
 * `token` names each registration's write, never the same twice.
 */
export function keptPasskeys(
	store: PasskeyStore,
	token: () => string,
	now: () => number = Date.now,
) {
	const holder = async (subject: string) => {
		const record = await store.subjects.read(subjectKey(subject));
		return record && holderOf(record);
	};
	/** Takes over a credential no holder lists (a failed registration's, or one between its writes), while it holds what was read. */
	const takeUnlisted = async (id: string, record: StoredPasskey): Promise<boolean> => {
		const key = credentialKey(id);
		const seen = await store.credentials.read(key);
		if (!seen) throw broken();
		const owner = await holder(keptOf(seen).subject);
		if (owner?.credentials.includes(id)) return false;
		const same = (r: StoredPasskey) => JSON.stringify(r) === JSON.stringify(seen);
		const taken = await store.credentials.update(key, (current) =>
			same(current) ? { value: record } : undefined,
		);
		return taken !== undefined && same(taken.before);
	};
	/** Strips a passkey's record to its subject, only where that subject holds it: one another subject took over is theirs. */
	const strip = (subject: string, id: string) =>
		store.credentials.update(credentialKey(id), (current) => {
			const kept = keptOf(current);
			if (kept.kind === "removed" || kept.subject !== subject) return undefined;
			return { value: stored({ v: 1, subject, removed: true }) };
		});
	/** The pending record the write named `written` kept, if the record is still that one. */
	const pendingOf = (record: StoredPasskey, written: string) => {
		const kept = keptOf(record);
		return kept.kind === "pending" && kept.token === written ? kept : undefined;
	};
	/** Takes an id off the subject's holder: `removed` where this call took it off, `empty` where none is left. */
	const delist = async (subject: string, id: string) => {
		const delisted = await store.subjects.update(subjectKey(subject), (current) => {
			const { credentials } = holderOf(current);
			if (!credentials.includes(id)) return undefined;
			return { value: stored({ ...current, credentials: credentials.filter((c) => c !== id) }) };
		});
		if (!delisted) return { removed: false, empty: true };
		// An update that wrote nothing answers what was there: removed only where this call took it off.
		const left = holderOf(delisted.after).credentials;
		const removed = holderOf(delisted.before).credentials.includes(id) && !left.includes(id);
		return { removed, empty: left.length === 0 };
	};
	const records = {
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
		/**
		 * Keeps a new passkey's record for the subject, whose handle it was made for, pending under a
		 * new token naming this write: no read takes it as a passkey until `listing` and `activated`.
		 * An id its holder lists is a conflict.
		 */
		written: async (
			subject: string,
			credential: Credential,
			max: number,
			nickname?: string,
		): Promise<{ readonly token: string } | "conflict" | "full" | "malformed"> => {
			// Only what reads back: a record no read can take would make every later use unavailable.
			if (!credentialOf(credential)) return "malformed";
			const { id, userHandle, ...rest } = credential;
			const kept = await holder(subject);
			if (kept?.handle !== userHandle) return "malformed";
			if (kept.credentials.length >= max) return "full";
			// Pending: listed or not, no read takes it as a passkey until `activated` names this write.
			const written = token();
			const record = stored({
				v: 2,
				subject,
				...rest,
				...(nickname ? { nickname } : {}),
				at: now(),
				pending: true,
				token: written,
			});
			const key = credentialKey(id);
			if ((await store.credentials.save(key, record, "endless")) === "exists") {
				if (!(await takeUnlisted(id, record))) return "conflict";
			}
			return { token: written };
		},
		/** Lists a record `written` kept: `registered` only where this update added the id; one listed already is another registration's (`conflict`). */
		listing: async (
			subject: string,
			id: string,
			max: number,
		): Promise<"registered" | "conflict" | "full"> => {
			const listed = await store.subjects.update(subjectKey(subject), (current) => {
				const { credentials } = holderOf(current);
				if (credentials.includes(id) || credentials.length >= max) return undefined;
				return { value: stored({ ...current, credentials: [...credentials, id] }) };
			});
			if (!listed) throw broken();
			if (holderOf(listed.before).credentials.includes(id)) return "conflict";
			return holderOf(listed.after).credentials.includes(id) ? "registered" : "full";
		},
		/**
		 * Makes the pending record the write `written` named the subject's passkey, and no other:
		 * `taken` where another registration wrote over it, another subject took it, or a removal ended it.
		 */
		activated: async (id: string, written: string): Promise<"activated" | "taken"> => {
			const changed = await store.credentials.update(credentialKey(id), (current) => {
				const kept = pendingOf(current, written);
				if (!kept) return undefined;
				const { kind: _, pending: __, token: ___, ...live } = kept;
				return { value: stored({ ...live, v: 1 }) };
			});
			// Written only over this write's pending record, so the record before tells whether this one wrote.
			return changed && pendingOf(changed.before, written) ? "activated" : "taken";
		},
		/** Strips the pending record the write `written` named, as a removed passkey's: a later registration takes it over. Another write's is its own. */
		unwritten: (subject: string, id: string, written: string) =>
			store.credentials.update(credentialKey(id), (current) =>
				pendingOf(current, written)
					? { value: stored({ v: 1, subject, removed: true }) }
					: undefined,
			),
		/** `written`, `listing` and `activated`, with nothing between; one not this write's to keep is a `conflict`, let go of. */
		register: async (subject: string, credential: Credential, max: number, nickname?: string) => {
			const wrote = await records.written(subject, credential, max, nickname);
			if (typeof wrote === "string") return wrote;
			const listed = await records.listing(subject, credential.id, max);
			if (listed !== "registered") {
				await records.unwritten(subject, credential.id, wrote.token);
				return listed;
			}
			if ((await records.activated(credential.id, wrote.token)) === "activated") return listed;
			await records.ended(subject, credential.id, wrote.token);
			return "conflict" as const;
		},
		/** Moves the count on from the one judged; another change first is a lost race. */
		count: async (judged: Credential, next: Credential): Promise<"counted" | "raced"> => {
			const changed = await store.credentials.update(credentialKey(judged.id), (current) => {
				// A removed passkey has no count to move on.
				if (passkeyOf(judged.id, current)?.credential.signCount !== judged.signCount)
					return undefined;
				return {
					value: stored({ ...current, signCount: next.signCount, backedUp: next.backedUp }),
				};
			});
			// Written only over the count judged, so the count before tells whether this one wrote.
			const before = changed && passkeyOf(judged.id, changed.before)?.credential.signCount;
			return before === judged.signCount ? "counted" : "raced";
		},
		/** The passkeys the subject's holder lists, as listed, in its order; one not held by it is left out. */
		listed: async (subject: string): Promise<readonly RegisteredPasskey[]> => {
			const ids = (await holder(subject))?.credentials ?? [];
			const listed: RegisteredPasskey[] = [];
			for (const id of ids) {
				const record = await store.credentials.read(credentialKey(id));
				const kept = record && keptOf(record);
				if (kept?.kind !== "passkey" || kept.subject !== subject) continue;
				listed.push({
					id,
					...(kept.nickname ? { nickname: kept.nickname } : {}),
					...(kept.transports ? { transports: kept.transports } : {}),
					backupEligible: kept.backupEligible,
					backedUp: kept.backedUp,
					...(kept.at === undefined ? {} : { at: kept.at }),
				});
			}
			return listed;
		},
		/** Names a passkey the subject's holder lists; none named is `unknown`. */
		renamed: async (
			subject: string,
			id: string,
			nickname: string,
		): Promise<"renamed" | "unknown"> => {
			if (!isCanonical(id, idBytes) || !(await holder(subject))?.credentials.includes(id)) {
				return "unknown";
			}
			const changed = await store.credentials.update(credentialKey(id), (current) => {
				const kept = keptOf(current);
				if (kept.kind !== "passkey" || kept.subject !== subject) return undefined;
				return { value: stored({ ...current, nickname }) };
			});
			// An update that wrote nothing answers what was there: renamed only where the name now stands.
			const after = changed && keptOf(changed.after);
			return after?.kind === "passkey" && after.subject === subject && after.nickname === nickname
				? "renamed"
				: "unknown";
		},
		/**
		 * Takes a passkey off the subject's holder, which ends its use, then strips its record to its
		 * holder alone. `removed` says this call took it off; `empty`, that the holder lists none after.
		 */
		removed: async (
			subject: string,
			id: string,
		): Promise<{ readonly removed: boolean; readonly empty: boolean }> => {
			const delisted = await delist(subject, id);
			if (delisted.removed) await strip(subject, id);
			return delisted;
		},
		/**
		 * Ends what the write named `written` left: the id off the subject's holder and its pending record
		 * stripped. A record another registration of the subject's left answers for itself, and stays.
		 */
		ended: async (
			subject: string,
			id: string,
			written: string,
		): Promise<{ readonly removed: boolean; readonly empty: boolean }> => {
			const record = await store.credentials.read(credentialKey(id));
			if (!record) throw broken();
			if (keptOf(record).subject === subject && !pendingOf(record, written)) {
				return { removed: false, empty: false };
			}
			const delisted = await delist(subject, id);
			await records.unwritten(subject, id, written);
			return delisted;
		},
		/** Takes every passkey off the subject's holder in one update, keeping its handle, then strips their records. `removed` counts what this call took off. */
		cleared: async (subject: string): Promise<{ readonly removed: number }> => {
			const delisted = await store.subjects.update(subjectKey(subject), (current) => {
				const holder = holderOf(current);
				if (holder.credentials.length === 0) return undefined;
				return { value: stored({ ...current, credentials: [] }) };
			});
			if (!delisted) return { removed: 0 };
			const left = new Set(holderOf(delisted.after).credentials);
			const taken = holderOf(delisted.before).credentials.filter((id) => !left.has(id));
			for (const id of taken) await strip(subject, id);
			return { removed: taken.length };
		},
	};
	return records;
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
