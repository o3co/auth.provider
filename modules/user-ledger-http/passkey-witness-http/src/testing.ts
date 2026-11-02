import type { z } from "zod";
import type { section } from "./section.ts";

export type PasskeyWitnessHttpSettings = z.input<typeof section>;

/** A credential for tests: 32 bytes of key material as base64url, of many byte values. */
export const testCredential = "Rw4kZ8nTq1Lp6Vx3Hb9Cm2Fj7Ds0Ga5Ye-Ku_Io3NzP";

/** The section of a test's configuration: the test credential, and three URLs at one origin under `.invalid`. */
export function passkeyWitnessHttpConfig(settings: Partial<PasskeyWitnessHttpSettings> = {}) {
	return {
		"passkey-witness-http": {
			"read-url": "https://ledger.example.invalid/passkey-witness/read",
			"enroll-url": "https://ledger.example.invalid/passkey-witness/enroll",
			"withdraw-url": "https://ledger.example.invalid/passkey-witness/withdraw",
			credential: testCredential,
			...settings,
		},
	};
}
