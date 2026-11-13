import { site } from "@mod/http";
import { defineModule, Unavailable } from "@mod/kernel";
import { factorKinds } from "@mod/mfa-extensions";
import { section } from "./section.ts";
import { algorithms, base32, keptSecret, matchedStep, readSecret } from "./totp.ts";

export default defineModule(
	{ name: "mfa-totp", replicaSafe: true, section, takes: [site] },
	(m) => [
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
					const { algorithm, digits, period: periodSeconds } = c.section;
					// RFC 4226 §4: a secret as long as its HMAC's output, 160 bits for SHA-1.
					const secret = base32(c.random.bytes(algorithms[algorithm]));
					const label = encodeURIComponent(`${issuer}:${subject}`);
					const query = new URLSearchParams({
						secret,
						issuer,
						algorithm,
						digits: String(digits),
						period: String(periodSeconds),
					});
					return {
						secret: keptSecret({ algorithm, digits, periodSeconds }, secret),
						show: {
							secret,
							otpauth_uri: `otpauth://totp/${label}?${query}`,
							algorithm,
							digits,
							period: periodSeconds,
						},
					};
				},
				verify: async (kept, state, proof) => {
					// A mark that does not read is a failure, never an answer: no attempt is spent on it.
					const read = readSecret(kept);
					if (!read) throw new Unavailable("mfa-totp");
					const { parameters, secret } = read;
					const step = matchedStep(
						parameters,
						secret,
						proof,
						c.clock.now(),
						c.section["drift-steps"],
					);
					if (step === undefined) return { kind: "invalid" };
					// The state is the last step used, as mfa kept it; a step at or before it is a replay.
					const last = typeof state === "number" ? state : Number.NEGATIVE_INFINITY;
					return step > last ? { kind: "valid", state: step } : { kind: "replayed" };
				},
			};
		}),
	],
);
