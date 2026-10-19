import { createHash } from "node:crypto";
import { defineModule } from "@mod/kernel";
import { factorKinds } from "@mod/mfa-extensions";

const codesPerSet = 10;
/** Crockford's base32: no letters that read like digits. */
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** Read whatever the case and hyphens; unsalted, as an 80-bit random code leaves nothing to look up. */
const digest = (code: string) =>
	createHash("sha256").update(code.toUpperCase().replaceAll("-", "")).digest("base64url");

export default defineModule({ name: "mfa-recovery", replicaSafe: true }, (m) => [
	m.contribute(factorKinds).by((c) => {
		/** 16 characters of 5 random bits each, 80 bits in all, shown as four groups of four. */
		const freshCode = () => {
			const chars = [...c.random.bytes(16)].map((b) => alphabet[b & 31]).join("");
			return (chars.match(/.{4}/g) ?? []).join("-");
		};
		return {
			kind: "recovery_code",
			amr: ["recovery"],
			addsSecondFactor: true,
			guessable: false,
			counts: false,
			// Whatever the subject holds, a new set is made, so mfa's reissue and first binding never fail on this kind.
			enroll: async () => {
				const codes = Array.from({ length: codesPerSet }, freshCode);
				return { secret: JSON.stringify(codes.map(digest)), show: codes };
			},
			// The state is the digests used so far; the secret is the set's digests.
			verify: async (secret, state, proof) => {
				const held = JSON.parse(secret) as string[];
				const used = Array.isArray(state) ? (state as string[]) : [];
				const given = digest(proof);
				// Digests of random codes: matching one by timing would still need its preimage.
				if (!held.includes(given)) return { kind: "invalid" };
				if (used.includes(given)) return { kind: "replayed" };
				return { kind: "valid", state: [...used, given], remaining: held.length - used.length - 1 };
			},
		};
	}),
]);
