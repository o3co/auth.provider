import type { KeptRecords } from "../records/records.ts";
import {
	broken,
	credentialKey,
	heldBy,
	holderOf,
	keptOf,
	removedOf,
	stored,
	subjectKey,
} from "../records/records.ts";
import type { PasskeyStore } from "../store.ts";
import type { Emptied, Lists } from "./joint.ts";

/** A removal's writes: an id off the list, the list emptied, and what a write that emptied it left. */
export function removingWith(
	store: PasskeyStore,
	{ together, delistedBy, listing }: Lists,
	holder: KeptRecords["holder"],
) {
	return {
		/**
		 * Takes an id off the subject's list in one change, which ends its use, stripping its record where it
		 * is the subject's; an old entry for another's record only frees its slot. `removed` says this call
		 * took it off; `empty`, that the holder lists none after; `emptied`, the holder left where it emptied the list.
		 */
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
		/**
		 * Empties the subject's list and strips every record of the subject it names, in one change, moving
		 * its fence on and keeping its handle; a subject with no holder gets one, under `fresh`. `removed`
		 * counts what this call took off.
		 */
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
		/**
		 * What the subject holds after a write that emptied its list left `emptied`, in one read that
		 * writes nothing: a `passkey` or a `pending` one listed; `none` where the holder is that one at
		 * that fence or later and every listed record reads as none of the subject's; else `unsure`.
		 * A holder that changes between its two reads, its handle, list or fence, is read from the start once more.
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
				const listed = again?.credentials.join("\n") === first.credentials.join("\n");
				if (again?.handle !== first.handle || again.fence !== first.fence || !listed) continue;
				if (held !== "none") return held;
				const same = first.handle === emptied.handle && first.fence >= emptied.fence;
				return same && !missing ? "none" : "unsure";
			}
			return "unsure";
		},
	};
}
