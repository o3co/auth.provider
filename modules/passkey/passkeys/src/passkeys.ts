import { createHash } from "node:crypto";
import { type Ceremonies, challengeOf, type Verification } from "@mod/webauthn";
import type { KeptChallenges } from "./challenges/challenges.ts";
import type { Passkeys, Requester } from "./contract.ts";
import type { KeptPasskeys } from "./records.ts";

export interface PasskeyParts {
	readonly ceremonies: Ceremonies;
	readonly records: KeptPasskeys;
	readonly challenges: KeptChallenges;
	readonly verification: Verification;
}

type Refusal = Extract<Awaited<ReturnType<Passkeys["assert"]>>, { kind: "refused" }>["reason"];
const refused = (reason: Refusal) => ({ kind: "refused" as const, reason });
/** A requester's part that is no non-empty string is its caller's mistake, thrown before the store is read. */
const partOf = (requester: Requester, part: "by" | "id") => {
	const value = (requester as Partial<Record<"by" | "id", unknown>> | null)?.[part];
	if (typeof value !== "string" || value === "") {
		throw new TypeError(`a passkey requester's ${part} must be a non-empty string`);
	}
	return value;
};
/**
 * Who asked, as the challenge keeps it: `by` in clear, and the id's digest, which keeps the record one
 * size whatever the id. The two are kept and compared apart, never joined into one string.
 */
const askerOf = (requester: Requester) => ({
	by: partOf(requester, "by"),
	requester: createHash("sha256").update(partOf(requester, "id")).digest("base64url"),
});

/** Assertions by the passkeys webauthn keeps, each found by the credential it names. */
export function passkeysOver(p: PasskeyParts): Passkeys {
	return {
		challenge: async (requester) => {
			const asker = askerOf(requester);
			const { options, challenge } = p.ceremonies.request([], p.verification);
			await p.challenges.open(challenge, { kind: "assertion", ...asker });
			return { options };
		},
		assert: async (response, requester) => {
			const asker = askerOf(requester);
			const answered = response as { id?: unknown; response?: { userHandle?: unknown } } | null;
			// Without a handle nothing ties the key to its holder: refused before the store is asked.
			const handle = answered?.response?.userHandle;
			if (typeof handle !== "string" || handle === "") return refused("no-user-handle");
			const challenge = challengeOf(response);
			if (challenge === undefined || typeof answered?.id !== "string") return refused("malformed");
			const opened = await p.challenges.take(challenge);
			// A format 1 challenge names no asker (`by` none), so it is taken and refused whatever it names.
			const mine =
				opened?.kind === "assertion" &&
				opened.by === asker.by &&
				opened.requester === asker.requester;
			if (!mine) {
				return refused("challenge");
			}
			const found = await p.records.passkey(answered.id);
			if (!found) return refused("unknown-credential");
			const holder = await p.records.holder(found.subject);
			if (!holder?.credentials.includes(answered.id)) return refused("unknown-credential");
			const credential = { ...found.credential, userHandle: holder.handle };
			const asserted = await p.ceremonies.assert(response, challenge, credential, p.verification);
			if (asserted.kind === "refused") return asserted;
			if ((await p.records.count(found, asserted.credential)) === "raced") {
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
