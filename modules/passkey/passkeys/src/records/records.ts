import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import { type Credential, credentialLimits, isCanonical } from "@mod/webauthn";
import { z } from "zod";
import type { RegisteredPasskey } from "../contract.ts";
import type { PasskeyStore, StoredPasskey } from "../store.ts";

export const { handleBytes, idBytes } = credentialLimits;

export interface Holder {
	readonly handle: string;
	readonly credentials: readonly string[];
	/** Moved on by each write that empties the list; 0 where none has (or 0.18 kept the holder). */
	readonly fence: number;
}

export interface Passkey {
	readonly subject: string;
	readonly credential: Omit<Credential, "userHandle">;
}

const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");
export const subjectKey = (subject: string) => `s-${hashOf(subject)}`;
export const credentialKey = (id: string) => `c-${hashOf(id)}`;
export const broken = () => new Unavailable("passkeys");

const canonical = (max: number) => z.string().refine((text) => isCanonical(text, max));
const holderShape = z.object({
	v: z.literal(1),
	handle: canonical(handleBytes),
	credentials: z.array(z.string()),
	fence: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
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
export function holderOf(record: StoredPasskey): Holder {
	const parsed = holderShape.safeParse(record);
	if (!parsed.success) throw broken();
	const { handle, credentials, fence = 0 } = parsed.data;
	return { handle, credentials, fence };
}

/** A kept passkey, or the subject a removed one was held by; unavailable for any other shape. */
export function keptOf(record: StoredPasskey) {
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

export const stored = (value: object) => value as unknown as StoredPasskey;

/** The pending record the write named `written` kept, if the record is still that one. */
export const pendingOf = (record: StoredPasskey, written: string) => {
	const kept = keptOf(record);
	return kept.kind === "pending" && kept.token === written ? kept : undefined;
};
/** A credential's record as a removal leaves it. */
export const removedOf = (subject: string) => stored({ v: 1, subject, removed: true });
/** Whether a record is the subject's passkey or pending one, as no removal left it. */
export const heldBy = (record: StoredPasskey | undefined, subject: string) => {
	const kept = record && keptOf(record);
	return kept !== undefined && kept.kind !== "removed" && kept.subject === subject;
};

/** Passkeys and their holders read in the shape written, and the writes that leave every list as it is. */
export function recordsOver(store: PasskeyStore) {
	const holder = async (subject: string) => {
		const record = await store.subjects.read(subjectKey(subject));
		return record && holderOf(record);
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
	};
	return records;
}

export type KeptRecords = ReturnType<typeof recordsOver>;
