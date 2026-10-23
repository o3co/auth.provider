import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import { type Credential, credentialLimits, credentialOf, isCanonical } from "@mod/webauthn";
import { z } from "zod";
import type { RegisteredPasskey } from "./contract.ts";
import type {
	ChallengeStore,
	ChangedPasskey,
	PasskeyStore,
	StoredChallenge,
	StoredPasskey,
} from "./store.ts";

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
	/** The pending record the write named `written` kept, if the record is still that one. */
	const pendingOf = (record: StoredPasskey, written: string) => {
		const kept = keptOf(record);
		return kept.kind === "pending" && kept.token === written ? kept : undefined;
	};
	/** A credential's record as a removal leaves it. */
	const removedOf = (subject: string) => stored({ v: 1, subject, removed: true });
	/** Whether a record is the subject's passkey or pending one, as no removal left it. */
	const heldBy = (record: StoredPasskey | undefined, subject: string) => {
		const kept = record && keptOf(record);
		return kept !== undefined && kept.kind !== "removed" && kept.subject === subject;
	};
	/** What a change of the subject's holder did to an id: `removed` where it took it off, `empty` where none is left. */
	const delistedBy = (changed: ChangedPasskey | undefined, id: string) => {
		const [before, after] = [changed?.before, changed?.after].map((r) =>
			r === undefined ? [] : holderOf(r).credentials,
		);
		return { removed: !!before?.includes(id) && !after?.includes(id), empty: after?.length === 0 };
	};
	const together = store.updateTogether.bind(store);
	/**
	 * The writes of a registration, an end, a removal and a clear: the credential's record and the
	 * subject's list, or the list and every record it names, in one change, so a list names an id
	 * exactly while the record names the subject, pending or a passkey.
	 */
	const joint = {
		/**
		 * Keeps a new passkey's record pending under `written` and lists its id, in one change. An id
		 * the record's holder lists is a conflict; a list at `max` that lacks it is full; a record no
		 * list holds (a removed one, or one 0.18 left) is taken over, an old entry for it kept.
		 */
		joined: async (
			subject: string,
			credential: Credential,
			max: number,
			nickname: string | undefined,
			written: string,
		): Promise<"written" | "conflict" | "full" | "malformed"> => {
			// Only what reads back: a record no read can take would make every later use unavailable.
			if (!credentialOf(credential)) return "malformed";
			const { id, userHandle, ...rest } = credential;
			if ((await holder(subject))?.handle !== userHandle) return "malformed";
			const record = stored({
				v: 2,
				subject,
				...rest,
				...(nickname ? { nickname } : {}),
				at: now(),
				pending: true,
				token: written,
			});
			let verdict: "written" | "conflict" | "full" = "written";
			await together(
				{ credentials: [credentialKey(id)], subjects: [subjectKey(subject)] },
				{
					// The holder another subject's record names is read with it, as its list decides.
					watch: (read) => {
						const kept = read.credentials[0] && keptOf(read.credentials[0]);
						return kept && kept.kind !== "removed" && kept.subject !== subject
							? { subjects: [subjectKey(kept.subject)] }
							: {};
					},
					change: (read) => {
						const [ours, owner] = read.subjects;
						if (!ours) throw broken();
						const listed = holderOf(ours).credentials;
						const kept = read.credentials[0] && keptOf(read.credentials[0]);
						// The list of the subject the record names, pending or a passkey: its own, or the one watched.
						const holders =
							kept === undefined || kept.kind === "removed"
								? []
								: kept.subject === subject
									? listed
									: owner === undefined
										? []
										: holderOf(owner).credentials;
						verdict = holders.includes(id)
							? "conflict"
							: !listed.includes(id) && listed.length >= max
								? "full"
								: "written";
						if (verdict !== "written") return {};
						const list = listed.includes(id) ? listed : [...listed, id];
						return {
							credentials: [{ value: record }],
							subjects: [{ value: stored({ ...ours, credentials: list }) }],
						};
					},
				},
			);
			return verdict;
		},
		/** Ends what the write named `written` left, in one change: off the list, its record stripped; any other record stays. */
		ended: async (subject: string, id: string, written: string) => {
			const changed = await together(
				{ credentials: [credentialKey(id)], subjects: [subjectKey(subject)] },
				{
					watch: () => ({}),
					change: (read) => {
						const [current, ours] = [read.credentials[0], read.subjects[0]];
						if (!current || !pendingOf(current, written) || !ours) return {};
						const listed = holderOf(ours).credentials;
						return {
							credentials: [{ value: removedOf(subject) }],
							subjects: [
								listed.includes(id)
									? { value: stored({ ...ours, credentials: listed.filter((c) => c !== id) }) }
									: undefined,
							],
						};
					},
				},
			);
			return delistedBy(changed.subjects[0], id);
		},
		/** Takes an id off the subject's list in one change, stripping its record where it is the subject's; an old entry for another's record only frees its slot. */
		removed: async (subject: string, id: string) => {
			const changed = await together(
				{ credentials: [credentialKey(id)], subjects: [subjectKey(subject)] },
				{
					watch: () => ({}),
					change: (read) => {
						const ours = read.subjects[0];
						const listed = ours === undefined ? [] : holderOf(ours).credentials;
						if (!ours || !listed.includes(id)) return {};
						return {
							credentials: [
								heldBy(read.credentials[0], subject) ? { value: removedOf(subject) } : undefined,
							],
							subjects: [
								{ value: stored({ ...ours, credentials: listed.filter((c) => c !== id) }) },
							],
						};
					},
				},
			);
			return delistedBy(changed.subjects[0], id);
		},
		/** Empties the subject's list and strips every record of the subject it names, in one change. */
		cleared: async (subject: string) => {
			const changed = await together(
				{ credentials: [], subjects: [subjectKey(subject)] },
				{
					watch: (read) => ({
						credentials: (read.subjects[0] ? holderOf(read.subjects[0]).credentials : []).map(
							credentialKey,
						),
					}),
					change: (read) => {
						const ours = read.subjects[0];
						if (!ours || holderOf(ours).credentials.length === 0) return {};
						return {
							credentials: read.credentials.map((r) =>
								heldBy(r, subject) ? { value: removedOf(subject) } : undefined,
							),
							subjects: [{ value: stored({ ...ours, credentials: [] }) }],
						};
					},
				},
			);
			const [before, after] = [changed.subjects[0]?.before, changed.subjects[0]?.after].map((r) =>
				r === undefined ? 0 : holderOf(r).credentials.length,
			);
			return { removed: (before ?? 0) - (after ?? 0) };
		},
	};
	const records = {
		holder,
		/** A new token naming a registration's write, made before the write so a retry writes the same one. */
		writeToken: token,
		joined: joint.joined,
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
		/** `joined` and `activated`, with nothing between; one not this write's to keep is a `conflict`, let go of. */
		register: async (subject: string, credential: Credential, max: number, nickname?: string) => {
			const written = token();
			const joined = await joint.joined(subject, credential, max, nickname, written);
			if (joined !== "written") return joined;
			if ((await records.activated(credential.id, written)) === "activated") {
				return "registered" as const;
			}
			await joint.ended(subject, credential.id, written);
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
		/** Takes an id off the subject's holder, which ends its use; see `joint`. `removed` says this call took it off; `empty`, that the holder lists none after. */
		removed: joint.removed,
		/** Ends what the write named `written` left; see `joint`. */
		ended: joint.ended,
		/** Takes every passkey off the subject's holder, keeping its handle; see `joint`. `removed` counts what this call took off. */
		cleared: joint.cleared,
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
