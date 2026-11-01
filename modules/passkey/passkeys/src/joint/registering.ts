import { type Credential, credentialOf } from "@mod/webauthn";
import type { KeptRecords } from "../records/records.ts";
import {
	broken,
	credentialKey,
	holderOf,
	keptOf,
	pendingOf,
	removedOf,
	stored,
	subjectKey,
} from "../records/records.ts";
import type { Lists } from "./joint.ts";

/** A registration's writes: a new passkey kept pending and listed, and what a write left ended. */
export function registeringWith(
	{ together, delistedBy, listing }: Lists,
	holder: KeptRecords["holder"],
	now: () => number,
) {
	return {
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
		/** Ends what the write named `written` left, in one change: off the list, its record stripped; any other record stays. Answers as `removed` does. */
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
	};
}
