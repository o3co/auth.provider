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

/** A ledger holding the users, answering users-http's password call and lookup by subject, and the section that points an app at it. */
export async function ledgerParty(users: readonly UserScene[]): Promise<Party> {
	const credential = randomBytes(32).toString("hex");
	const ledger = await fakeHttp((asked) => {
		// Anything but the two calls with the credential is unavailable, so a wrong set-up shows.
		const call = asked.method === "POST" && ["/verify", "/subject"].includes(asked.path);
		if (!call || asked.headers.authorization !== `Bearer ${credential}`) return { status: 404 };
		const given = JSON.parse(asked.body);
		const user =
			asked.path === "/subject"
				? users.find((u) => (u.subject ?? u.identifier) === given.subject)
				: users.find((u) => u.identifier === given.email && u.password === given.password);
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
	const verifyUrl = `${ledger.base}/verify`;
	const subjectUrl = `${ledger.base}/subject`;
	return {
		base: ledger.base,
		config: { "users-http": { "verify-url": verifyUrl, "subject-url": subjectUrl, credential } },
		stop: ledger.stop,
	};
}
