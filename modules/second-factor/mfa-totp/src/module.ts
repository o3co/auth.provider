import { site } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { factorKinds } from "@mod/mfa-extensions";
import { algorithm, base32, digits, matchedStep, periodSeconds } from "./totp.ts";

/** RFC 4226 recommends 160 bits, the length of a SHA-1 output. */
const secretBytes = 20;

export default defineModule({ name: "mfa-totp", replicaSafe: true, takes: [site] }, (m) => [
	m.contribute(factorKinds).by(async (c) => {
		const origin = (await c.get(site)).origin;
		const issuer = origin ? new URL(origin).host : "auth";
		return {
			kind: "totp",
			amr: ["otp"],
			addsSecondFactor: true,
			guessable: true,
			counts: true,
			enroll: async (subject) => {
				const secret = base32(c.random.bytes(secretBytes));
				const label = encodeURIComponent(`${issuer}:${subject}`);
				const query = new URLSearchParams({
					secret,
					issuer,
					algorithm,
					digits: String(digits),
					period: String(periodSeconds),
				});
				return {
					secret,
					show: {
						secret,
						otpauth_uri: `otpauth://totp/${label}?${query}`,
						algorithm,
						digits,
						period: periodSeconds,
					},
				};
			},
			verify: async (secret, state, proof) => {
				const step = matchedStep(secret, proof, c.clock.now());
				if (step === undefined) return { kind: "invalid" };
				// The state is the last step used, as mfa kept it; a step at or before it is a replay.
				const last = typeof state === "number" ? state : Number.NEGATIVE_INFINITY;
				return step > last ? { kind: "valid", state: step } : { kind: "replayed" };
			},
		};
	}),
]);
