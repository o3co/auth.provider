import type { Credential } from "@mod/webauthn";
import { jointOver } from "./joint/joint.ts";
import { recordsOver } from "./records/records.ts";
import type { PasskeyStore } from "./store.ts";

export type { KeptChallenges, Purpose } from "./challenges/challenges.ts";
export type { Emptied } from "./joint/joint.ts";
export type { Holder, Passkey } from "./records/records.ts";

/**
 * Passkeys and their holders, written only in canonical form and read only in the shape written;
 * `token` names each registration's write, never the same twice.
 */
export function keptPasskeys(
	store: PasskeyStore,
	token: () => string,
	now: () => number = Date.now,
) {
	const records = recordsOver(store);
	const joint = jointOver(store, records.holder, now);
	return {
		...records,
		...joint,
		/** A new token naming a registration's write, made before the write so a retry writes the same one. */
		writeToken: token,
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
	};
}

export type KeptPasskeys = ReturnType<typeof keptPasskeys>;
