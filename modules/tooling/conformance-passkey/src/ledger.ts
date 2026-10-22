import { randomBytes } from "node:crypto";
import { fakeHttp, type Party } from "@mod/conformance";

const calls = [
	"/passkey-witness/read",
	"/passkey-witness/enroll",
	"/passkey-witness/withdraw",
	"/passkey-witness/clear",
];

/**
 * A ledger answering passkey-witness-http's calls as an operator's keeps them: a mark per subject,
 * set only where none is, withdrawn only by its token, cleared whatever it holds; and the section
 * that points an app at it.
 */
export async function witnessLedger(): Promise<Party> {
	const credential = randomBytes(32).toString("hex");
	const marks = new Map<string, string>();
	const ledger = await fakeHttp((asked) => {
		// Anything but the calls held with the credential is unavailable, so a wrong set-up shows.
		if (asked.method !== "POST" || !calls.includes(asked.path)) return { status: 404 };
		if (asked.headers.authorization !== `Bearer ${credential}`) return { status: 404 };
		const given = JSON.parse(asked.body) as { subject?: string; token?: string };
		const subject = String(given.subject);
		if (asked.path === "/passkey-witness/read") return { json: { enrolled: marks.has(subject) } };
		if (asked.path === "/passkey-witness/enroll") {
			if (!marks.has(subject)) marks.set(subject, String(given.token));
			return { json: { owner: marks.get(subject) === given.token } };
		}
		// One row per subject: a withdraw compares the token and deletes on that row alone.
		if (asked.path === "/passkey-witness/withdraw") {
			if (marks.get(subject) === given.token) marks.delete(subject);
			return { status: 204 };
		}
		marks.delete(subject);
		return { status: 204 };
	});
	const at = (path: string) => `${ledger.base}${path}`;
	return {
		base: ledger.base,
		config: {
			"passkey-witness-http": {
				"read-url": at("/passkey-witness/read"),
				"enroll-url": at("/passkey-witness/enroll"),
				"withdraw-url": at("/passkey-witness/withdraw"),
				"clear-url": at("/passkey-witness/clear"),
				credential,
			},
		},
		stop: ledger.stop,
	};
}
