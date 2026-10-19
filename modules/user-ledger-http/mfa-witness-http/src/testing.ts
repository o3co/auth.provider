import { randomBytes } from "node:crypto";
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

/** A call made to a fake ledger, as a fake HTTP server hands it on; header names lower case. */
export interface LedgerCall {
	readonly method: string;
	readonly path: string;
	readonly headers: Readonly<Record<string, string | undefined>>;
	readonly body: string;
}

/** A fake ledger's answer: a status, or a JSON body answered 200. */
export interface LedgerAnswer {
	readonly status?: number;
	readonly json?: unknown;
}

const calls = ["/mfa-witness/read", "/mfa-witness/enroll", "/mfa-witness/clear"];

/**
 * A fake ledger keeping mfa's witness as an operator's ledger does, behind a credential of its own:
 * a mark per subject, set only where none is. Its answer to mfa-witness-http's calls (none for a
 * call not its own), and the section pointing mfa-witness-http at it once it listens at `base`.
 */
export function witnessLedger() {
	const credential = randomBytes(32).toString("base64url");
	const marks = new Map<string, string>();
	return {
		answer(call: LedgerCall): LedgerAnswer | undefined {
			if (!calls.includes(call.path)) return undefined;
			// Anything but a call with the credential is not found, so a wrong set-up shows.
			if (call.method !== "POST" || call.headers.authorization !== `Bearer ${credential}`) {
				return { status: 404 };
			}
			const { subject, token } = JSON.parse(call.body) as { subject?: string; token?: string };
			const held = String(subject);
			if (call.path === "/mfa-witness/read") return { json: { enrolled: marks.has(held) } };
			if (call.path === "/mfa-witness/enroll") {
				if (!marks.has(held)) marks.set(held, String(token));
				return { json: { owner: marks.get(held) === token } };
			}
			marks.delete(held);
			return { status: 204 };
		},
		section: (base: string) => ({
			"mfa-witness-http": {
				"read-url": `${base}/mfa-witness/read`,
				"enroll-url": `${base}/mfa-witness/enroll`,
				"clear-url": `${base}/mfa-witness/clear`,
				credential,
			},
		}),
	};
}
