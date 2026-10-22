import { randomBytes } from "node:crypto";
import type { z } from "zod";
import type { section } from "./section.ts";

export type PasskeyWitnessHttpSettings = z.input<typeof section>;

/** A credential for tests: 32 bytes of key material as base64url, of many byte values. */
export const testCredential = "Rw4kZ8nTq1Lp6Vx3Hb9Cm2Fj7Ds0Ga5Ye-Ku_Io3NzP";

/** The section of a test's configuration: the test credential, and four URLs at one origin under `.invalid`. */
export function passkeyWitnessHttpConfig(settings: Partial<PasskeyWitnessHttpSettings> = {}) {
	return {
		"passkey-witness-http": {
			"read-url": "https://ledger.example.invalid/passkey-witness/read",
			"enroll-url": "https://ledger.example.invalid/passkey-witness/enroll",
			"withdraw-url": "https://ledger.example.invalid/passkey-witness/withdraw",
			"clear-url": "https://ledger.example.invalid/passkey-witness/clear",
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

const calls = [
	"/passkey-witness/read",
	"/passkey-witness/enroll",
	"/passkey-witness/withdraw",
	"/passkey-witness/clear",
];

/**
 * A fake ledger keeping the passkey witness as an operator's ledger does, behind a credential of its
 * own: a mark per subject, set only where none is, withdrawn only by its token. Its answer to passkey-witness-http's calls (none for a
 * call not its own), and the section pointing passkey-witness-http at it once it listens at `base`.
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
			if (call.path === "/passkey-witness/read") return { json: { enrolled: marks.has(held) } };
			if (call.path === "/passkey-witness/enroll") {
				if (!marks.has(held)) marks.set(held, String(token));
				return { json: { owner: marks.get(held) === token } };
			}
			if (call.path === "/passkey-witness/withdraw") {
				if (marks.get(held) === token) marks.delete(held);
				return { status: 204 };
			}
			marks.delete(held);
			return { status: 204 };
		},
		section: (base: string) => ({
			"passkey-witness-http": {
				"read-url": `${base}/passkey-witness/read`,
				"enroll-url": `${base}/passkey-witness/enroll`,
				"withdraw-url": `${base}/passkey-witness/withdraw`,
				"clear-url": `${base}/passkey-witness/clear`,
				credential,
			},
		}),
	};
}
