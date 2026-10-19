import { randomBytes } from "node:crypto";
import { fakeHttp, type Party } from "@mod/conformance";
import type { UserScene } from "./area.ts";
import { addressOf } from "./pattern.ts";

/** Why a ledger cannot hold these users, or nothing where it can. */
export function unledgered(users: readonly UserScene[]): string | undefined {
	const lacks = [
		users.some((u) => u.upstream) && "upstream links",
		users.some((u) => u.bcrypt) && "a password hash other than scrypt",
	].filter((why) => why !== false);
	return lacks.length > 0 ? `gives users a ledger cannot hold: ${lacks.join(", ")}` : undefined;
}

/** What a ledger keeps for mfa-witness-http: a mark per subject, set only where none is, as an operator's ledger keeps it. */
function witnessKeeper() {
	const marks = new Map<string, string>();
	return (path: string, given: { subject?: string; token?: string }) => {
		const subject = String(given.subject);
		if (path === "/mfa-witness/read") return { json: { enrolled: marks.has(subject) } };
		if (path === "/mfa-witness/enroll") {
			if (!marks.has(subject)) marks.set(subject, String(given.token));
			return { json: { owner: marks.get(subject) === given.token } };
		}
		marks.delete(subject);
		return { status: 204 };
	};
}

/**
 * A ledger answering users-http's password call and lookup by subject for the users given, and
 * mfa-witness-http's calls where `witness`; and the sections that point an app at it.
 */
export async function ledgerParty(held: {
	readonly users?: readonly UserScene[];
	readonly witness?: boolean;
}): Promise<Party> {
	const credential = randomBytes(32).toString("hex");
	const users = held.users;
	const witness = held.witness ? witnessKeeper() : undefined;
	const userCalls = users ? ["/verify", "/subject"] : [];
	const witnessCalls = witness
		? ["/mfa-witness/read", "/mfa-witness/enroll", "/mfa-witness/clear"]
		: [];
	const ledger = await fakeHttp((asked) => {
		// Anything but the calls held with the credential is unavailable, so a wrong set-up shows.
		const call = asked.method === "POST" && [...userCalls, ...witnessCalls].includes(asked.path);
		if (!call || asked.headers.authorization !== `Bearer ${credential}`) return { status: 404 };
		const given = JSON.parse(asked.body);
		if (witness && witnessCalls.includes(asked.path)) return witness(asked.path, given);
		const user =
			asked.path === "/subject"
				? users?.find((u) => (u.subject ?? u.identifier) === given.subject)
				: users?.find((u) => u.identifier === given.email && u.password === given.password);
		if (!user) return { status: asked.path === "/subject" ? 404 : 401 };
		const { emailVerified } = user;
		const email = emailVerified === undefined ? user.email : addressOf(user);
		return {
			json: {
				id: user.subject ?? user.identifier,
				username: user.identifier,
				...(email ? { email } : {}),
				...(emailVerified === undefined ? {} : { emailVerified }),
			},
		};
	});
	const at = (path: string) => `${ledger.base}${path}`;
	return {
		base: ledger.base,
		config: {
			...(users
				? {
						"users-http": {
							"verify-url": at("/verify"),
							"subject-url": at("/subject"),
							credential,
						},
					}
				: {}),
			...(witness
				? {
						"mfa-witness-http": {
							"read-url": at("/mfa-witness/read"),
							"enroll-url": at("/mfa-witness/enroll"),
							"clear-url": at("/mfa-witness/clear"),
							credential,
						},
					}
				: {}),
		},
		stop: ledger.stop,
	};
}
