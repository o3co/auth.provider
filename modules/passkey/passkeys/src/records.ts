import { type Credential, credentialOf } from "@mod/webauthn";
import {
	broken,
	credentialKey,
	heldBy,
	holderOf,
	keptOf,
	pendingOf,
	recordsOver,
	removedOf,
	stored,
	subjectKey,
} from "./records/records.ts";
import type { ChangedPasskey, PasskeyStore, StoredPasskey } from "./store.ts";

export type { KeptChallenges, Purpose } from "./challenges/challenges.ts";
export type { Holder, Passkey } from "./records/records.ts";

/** The holder a write that emptied its list left: its handle, which names the holder's incarnation, and its fence. */
export interface Emptied {
	readonly handle: string;
	readonly fence: number;
}

/**
 * Passkeys and their holders, written only in canonical form and read only in the shape written;
 * `token` names each registration's write, never the same twice.
 */
export function keptPasskeys(
	store: PasskeyStore,
	token: () => string,
	now: () => number = Date.now,
) {
	/** The holder a change left, where it emptied the list. */
	const emptiedBy = (changed: ChangedPasskey | undefined): Emptied | undefined => {
		const [before, after] = [changed?.before, changed?.after].map((r) => r && holderOf(r));
		if (!after || after.credentials.length > 0 || after.fence === before?.fence) return undefined;
		return { handle: after.handle, fence: after.fence };
	};
	/** What a change of the subject's holder did to an id: `removed` where it took it off, `empty` where none is left, `emptied` the holder left where it emptied the list. */
	const delistedBy = (changed: ChangedPasskey | undefined, id: string) => {
		const [before, after] = [changed?.before, changed?.after].map((r) =>
			r === undefined ? [] : holderOf(r).credentials,
		);
		const removed = !!before?.includes(id) && !after?.includes(id);
		const emptied = removed ? emptiedBy(changed) : undefined;
		return { removed, empty: after?.length === 0, ...(emptied && { emptied }) };
	};
	/** The subject's holder listing `list`, its fence moved on where `list` empties it. */
	const listing = (ours: StoredPasskey, list: readonly string[]) => {
		const held = holderOf(ours);
		const fence = list.length === 0 && held.credentials.length > 0 ? held.fence + 1 : held.fence;
		return stored({ ...ours, credentials: list, fence });
	};
	const records = recordsOver(store);
	const { holder } = records;
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
			let verdict: "written" | "conflict" | "full" | "malformed" = "written";
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
						// Checked again in the change: the holder may have been made anew since.
						if (holderOf(ours).handle !== userHandle) {
							verdict = "malformed";
							return {};
						}
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
						const rest = listed.filter((c) => c !== id);
						return {
							credentials: [{ value: removedOf(subject) }],
							subjects: [listed.includes(id) ? { value: listing(ours, rest) } : undefined],
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
						const rest = listed.filter((c) => c !== id);
						return {
							credentials: [
								heldBy(read.credentials[0], subject) ? { value: removedOf(subject) } : undefined,
							],
							subjects: [{ value: listing(ours, rest) }],
						};
					},
				},
			);
			return delistedBy(changed.subjects[0], id);
		},
		/** Empties the subject's list and strips every record of the subject it names, in one change, moving its fence on; a subject with no holder gets one, under `fresh`. */
		cleared: async (subject: string, fresh: string) => {
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
						const made = stored({ v: 1, handle: fresh, credentials: [], fence: 1 });
						if (!ours) return { subjects: [{ value: made }] };
						const held = holderOf(ours);
						return {
							credentials: read.credentials.map((r) =>
								heldBy(r, subject) ? { value: removedOf(subject) } : undefined,
							),
							subjects: [{ value: stored({ ...ours, credentials: [], fence: held.fence + 1 }) }],
						};
					},
				},
			);
			const [before, after] = [changed.subjects[0]?.before, changed.subjects[0]?.after].map((r) =>
				r === undefined ? undefined : holderOf(r),
			);
			if (!after) throw broken();
			return {
				removed: (before?.credentials.length ?? 0) - after.credentials.length,
				emptied: { handle: after.handle, fence: after.fence },
			};
		},
	};
	const kept = {
		...records,
		/** A new token naming a registration's write, made before the write so a retry writes the same one. */
		writeToken: token,
		joined: joint.joined,
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
		/** Takes an id off the subject's holder, which ends its use; see `joint`. `removed` says this call took it off; `empty`, that the holder lists none after. */
		removed: joint.removed,
		/** Ends what the write named `written` left; see `joint`. */
		ended: joint.ended,
		/** Takes every passkey off the subject's holder, keeping its handle; see `joint`. `removed` counts what this call took off. */
		cleared: joint.cleared,
		/**
		 * What the subject holds after a write that emptied its list left `emptied`, in one read that
		 * writes nothing: a `passkey` or a `pending` one listed; `none` where the holder is that one at
		 * that fence or later and every listed record reads as none of the subject's; else `unsure`.
		 * A holder that changes between its two reads is read from the start once more.
		 */
		afterRemoval: async (
			subject: string,
			emptied: Emptied,
		): Promise<"passkey" | "pending" | "none" | "unsure"> => {
			for (let tries = 0; tries < 2; tries++) {
				const first = await holder(subject);
				if (!first) return "unsure";
				let held: "passkey" | "pending" | "none" = "none";
				let missing = false;
				for (const id of first.credentials) {
					const record = await store.credentials.read(credentialKey(id));
					const kept = record && keptOf(record);
					if (kept === undefined) missing = true;
					else if (kept.kind !== "removed" && kept.subject === subject) {
						held = kept.kind === "passkey" ? "passkey" : held === "none" ? "pending" : held;
					}
				}
				const again = await holder(subject);
				if (again?.handle !== first.handle || again.fence !== first.fence) continue;
				if (held !== "none") return held;
				const same = first.handle === emptied.handle && first.fence >= emptied.fence;
				return same && !missing ? "none" : "unsure";
			}
			return "unsure";
		},
	};
	return kept;
}

export type KeptPasskeys = ReturnType<typeof keptPasskeys>;
