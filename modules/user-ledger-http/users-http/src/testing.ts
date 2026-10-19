/** For tests: a fake ledger speaking users-http's calls, for a scene or an operator trying an app. */
import { randomBytes } from "node:crypto";

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

/** A user the fake ledger holds: its password in the clear, as only a test holds one. */
export interface LedgerUser {
	readonly identifier: string;
	readonly password: string;
	/** The subject; the identifier when left out. */
	readonly subject?: string;
	readonly email?: string;
	readonly emailVerified?: boolean;
}

const calls = ["/verify", "/subject"];

/**
 * A fake ledger holding these users behind a credential of its own: its answer to users-http's
 * password call and lookup by subject (none for a call not its own), and the section pointing
 * users-http at it once it listens at `base`.
 */
export function usersLedger(users: readonly LedgerUser[]) {
	const credential = randomBytes(32).toString("hex");
	return {
		answer(call: LedgerCall): LedgerAnswer | undefined {
			if (!calls.includes(call.path)) return undefined;
			// Anything but a call with the credential is not found, so a wrong set-up shows.
			if (call.method !== "POST" || call.headers.authorization !== `Bearer ${credential}`) {
				return { status: 404 };
			}
			const given = JSON.parse(call.body);
			const user =
				call.path === "/subject"
					? users.find((u) => (u.subject ?? u.identifier) === given.subject)
					: users.find((u) => u.identifier === given.email && u.password === given.password);
			if (!user) return { status: call.path === "/subject" ? 404 : 401 };
			return {
				json: {
					id: user.subject ?? user.identifier,
					username: user.identifier,
					...(user.email === undefined ? {} : { email: user.email }),
					...(user.emailVerified === undefined ? {} : { emailVerified: user.emailVerified }),
				},
			};
		},
		section: (base: string) => ({
			"users-http": {
				"verify-url": `${base}/verify`,
				"subject-url": `${base}/subject`,
				credential,
			},
		}),
	};
}
