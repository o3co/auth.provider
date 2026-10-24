import type { z } from "zod";
import type { section } from "./section.ts";

export type MfaWitnessHttpSettings = z.input<typeof section>;

/** A credential for tests: 32 bytes of key material as base64url, of many byte values. */
export const testCredential = "Rw4kZ8nTq1Lp6Vx3Hb9Cm2Fj7Ds0Ga5Ye-Ku_Io3NzP";

/** The section of a test's configuration: the test credential, and three URLs at one origin under `.invalid`. */
export function mfaWitnessHttpConfig(settings: Partial<MfaWitnessHttpSettings> = {}) {
	return {
		"mfa-witness-http": {
			"read-url": "https://ledger.example.invalid/mfa-witness/read",
			"enroll-url": "https://ledger.example.invalid/mfa-witness/enroll",
			"clear-url": "https://ledger.example.invalid/mfa-witness/clear",
			credential: testCredential,
			...settings,
		},
	};
}
