import { createHash } from "node:crypto";
import { type Ceremonies, challengeOf, type Verification } from "@mod/webauthn";
import type { Passkeys } from "./contract.ts";
import type { KeptChallenges, KeptPasskeys } from "./records.ts";

export interface PasskeyParts {
	readonly ceremonies: Ceremonies;
	readonly records: KeptPasskeys;
	readonly challenges: KeptChallenges;
	readonly verification: Verification;
}

type Refusal = Extract<Awaited<ReturnType<Passkeys["assert"]>>, { kind: "refused" }>["reason"];
const refused = (reason: Refusal) => ({ kind: "refused" as const, reason });
// A digest keeps the challenge's record one size, whatever the requester sent.
const digestOf = (requester: string) => createHash("sha256").update(requester).digest("base64url");

/** Assertions by the passkeys webauthn keeps, each found by the credential it names. */
export function passkeysOver(p: PasskeyParts): Passkeys {
	return {
		challenge: async (requester) => {
			const { options, challenge } = p.ceremonies.request([], p.verification);
			await p.challenges.open(challenge, { kind: "assertion", requester: digestOf(requester) });
			return { options };
		},
		assert: async (response, requester) => {
			const answered = response as { id?: unknown; response?: { userHandle?: unknown } } | null;
			// Without a handle nothing ties the key to its holder: refused before the store is asked.
			const handle = answered?.response?.userHandle;
			if (typeof handle !== "string" || handle === "") return refused("no-user-handle");
			const challenge = challengeOf(response);
			if (challenge === undefined || typeof answered?.id !== "string") return refused("malformed");
			const opened = await p.challenges.take(challenge);
			if (opened?.kind !== "assertion" || opened.requester !== digestOf(requester)) {
				return refused("challenge");
			}
			const found = await p.records.passkey(answered.id);
			if (!found) return refused("unknown-credential");
			const holder = await p.records.holder(found.subject);
			if (!holder?.credentials.includes(answered.id)) return refused("unknown-credential");
			const credential = { ...found.credential, userHandle: holder.handle };
			const asserted = await p.ceremonies.assert(response, challenge, credential, p.verification);
			if (asserted.kind === "refused") return asserted;
			if ((await p.records.count(credential, asserted.credential)) === "raced") {
				return refused("raced");
			}
			return {
				kind: "asserted",
				subject: found.subject,
				challengedAt: opened.at,
				userVerified: asserted.userVerified,
				backupEligible: credential.backupEligible,
			};
		},
	};
}
