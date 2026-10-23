import { fakeHttp, type Party } from "@mod/conformance";
import { mfaWitnessLedger, usersLedger } from "@mod/ledger-fakes";
import type { UserScene } from "./area.ts";
import { addressOf } from "./pattern.ts";

/** Why a ledger cannot hold these users, or nothing where it can. */
export function unledgered(users: readonly UserScene[]): string | undefined {
	const lacks = [users.some((u) => u.bcrypt) && "a password hash other than scrypt"].filter(
		(why) => why !== false,
	);
	return lacks.length > 0 ? `gives users a ledger cannot hold: ${lacks.join(", ")}` : undefined;
}

/**
 * A ledger on one server answering users-http's calls for the users given (the password call, and
 * lookups by subject and by upstream identity), and mfa-witness-http's where `witness`, each as
 * ledger-fakes plays it; and the sections that point an app at it.
 */
export async function ledgerParty(held: {
	readonly users?: readonly UserScene[];
	readonly witness?: boolean;
}): Promise<Party> {
	const users =
		held.users &&
		usersLedger(
			held.users.map((u) => {
				// Its own address, or one made up where only its verification is said.
				const email = u.emailVerified === undefined ? u.email : addressOf(u);
				return {
					identifier: u.identifier,
					password: u.password,
					...(u.subject ? { subject: u.subject } : {}),
					...(email === undefined ? {} : { email }),
					...(u.emailVerified === undefined ? {} : { emailVerified: u.emailVerified }),
					...(u.upstream ? { upstream: u.upstream } : {}),
				};
			}),
		);
	const witness = held.witness ? mfaWitnessLedger() : undefined;
	// Anything but a call one of them holds is unavailable, so a wrong set-up shows.
	const ledger = await fakeHttp(
		(asked) => users?.answer(asked) ?? witness?.answer(asked) ?? { status: 404 },
	);
	const userUrls = users?.urls(ledger.base);
	const witnessUrls = witness?.urls(ledger.base);
	return {
		base: ledger.base,
		config: {
			...(users && userUrls
				? {
						"users-http": {
							"verify-url": userUrls.verify,
							"subject-url": userUrls.subject,
							"upstream-url": userUrls.upstream,
							credential: users.credential,
						},
					}
				: {}),
			...(witness && witnessUrls
				? {
						"mfa-witness-http": {
							"read-url": witnessUrls.read,
							"enroll-url": witnessUrls.enroll,
							"clear-url": witnessUrls.clear,
							"withdraw-url": witnessUrls.withdraw,
							credential: witness.credential,
						},
					}
				: {}),
		},
		stop: ledger.stop,
	};
}
