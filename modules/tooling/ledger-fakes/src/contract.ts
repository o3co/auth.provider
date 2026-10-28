import { randomBytes } from "node:crypto";
import { type LedgerUserAnswer, ledgerRoutes, usersWire, witnessWire } from "@mod/ledger-wire";

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

/** A user the fake user ledger holds: its password in the clear, as only a test holds one. */
export interface LedgerUser {
	readonly identifier: string;
	readonly password: string;
	/** The subject; the identifier when left out. */
	readonly subject?: string;
	readonly email?: string;
	readonly emailVerified?: boolean;
	readonly name?: string;
	/** The upstream identity the ledger links to this user. */
	readonly upstream?: { readonly idp: string; readonly subject: string };
}

/**
 * A fake ledger behind a credential of its own: its answer to a call (none for a call not its own;
 * a bare `404` for one of its own without the credential, so a wrong set-up shows), and where it
 * serves each call once it listens at `base`.
 */
export interface FakeLedger<Call extends string, Optional extends Call = never> {
	answer(call: LedgerCall): LedgerAnswer | undefined;
	/** Each call's URL; one of `Optional` is left out where the ledger has no route for it. */
	urls(
		base: string,
	): Readonly<Record<Exclude<Call, Optional>, string> & Partial<Record<Optional, string>>>;
	readonly credential: string;
}

type Routes = Readonly<Record<string, string>>;

/** Each route at `base`, keyed by its call. */
const at = <R extends Routes>(routes: R, base: string) =>
	Object.fromEntries(Object.entries(routes).map(([name, path]) => [name, `${base}${path}`])) as {
		readonly [K in keyof R]: string;
	};

/** Whether a call is one of the routes, and whether it carries the credential, by POST. */
const ownCall = (routes: Routes, call: LedgerCall) => Object.values(routes).includes(call.path);
const authorized = (credential: string, call: LedgerCall) =>
	call.method === "POST" && call.headers.authorization === `Bearer ${credential}`;

/** A fake user ledger holding these users, as users-http calls it: the password call, and lookups by subject and by upstream identity. */
export function usersLedger(
	users: readonly LedgerUser[],
): FakeLedger<keyof typeof ledgerRoutes.users> {
	const routes = ledgerRoutes.users;
	const credential = randomBytes(32).toString("hex");
	const answerOf = (user: LedgerUser): LedgerUserAnswer => ({
		id: user.subject ?? user.identifier,
		username: user.identifier,
		...(user.email === undefined ? {} : { email: user.email }),
		...(user.emailVerified === undefined ? {} : { emailVerified: user.emailVerified }),
		...(user.name === undefined ? {} : { name: user.name }),
	});
	return {
		credential,
		urls: (base) => at(routes, base),
		answer(call) {
			if (!ownCall(routes, call)) return undefined;
			if (!authorized(credential, call)) return { status: 404 };
			// The bodies users-http sends, as the wire builds them.
			const given = JSON.parse(call.body) as Partial<
				ReturnType<typeof usersWire.verify> & ReturnType<typeof usersWire.byUpstream>
			>;
			const user =
				call.path === routes.subject
					? users.find((u) => (u.subject ?? u.identifier) === given.subject)
					: call.path === routes.upstream
						? users.find(
								(u) => u.upstream?.idp === given.idp && u.upstream?.subject === given.subject,
							)
						: users.find((u) => u.identifier === given.email && u.password === given.password);
			// A lookup says it knows no such user; a bare 404 above is a wrong set-up.
			if (!user) {
				return call.path === routes.verify
					? { status: usersWire.refused }
					: { status: 404, json: { error: usersWire.noUser[404] } };
			}
			return { json: answerOf(user) };
		},
	};
}

/** The marks a witness ledger keeps: one per subject, set only where none is, withdrawn only by its token. */
function marksKept() {
	const marks = new Map<string, string>();
	return {
		mark: (subject: string) => marks.get(subject),
		enroll(subject: string, token: string) {
			if (!marks.has(subject)) marks.set(subject, token);
			return { owner: marks.get(subject) === token };
		},
		// One row per subject: a withdraw compares the token and deletes on that row alone.
		withdraw(subject: string, token: string) {
			if (marks.get(subject) === token) marks.delete(subject);
		},
		clear: (subject: string) => void marks.delete(subject),
	};
}

/** A witness's read: whether the subject is marked, naming the mark's token. */
const markRead = (mark: string | undefined) =>
	mark === undefined ? { enrolled: false } : { enrolled: true, token: mark };

/** A witness ledger's answer to one of its calls, given the routes it keeps. */
function witnessAnswer(
	routes: Routes,
	kept: ReturnType<typeof marksKept>,
	call: LedgerCall,
): LedgerAnswer {
	const given = JSON.parse(call.body) as Partial<ReturnType<typeof witnessWire.withdraw>>;
	const subject = String(given.subject);
	if (call.path === routes.read) return { json: markRead(kept.mark(subject)) };
	if (call.path === routes.enroll) return { json: kept.enroll(subject, String(given.token)) };
	if (call.path === routes.withdraw) kept.withdraw(subject, String(given.token));
	// The one other write: mfa's clear (the passkey witness keeps no such route).
	else kept.clear(subject);
	return { status: witnessWire.written };
}

/**
 * A fake ledger keeping mfa's witness: a read names the mark's token. Made `withdraw: false`, it
 * plays a ledger with no withdraw route, and serves no URL for it.
 */
export function mfaWitnessLedger(
	options: { readonly withdraw?: boolean } = {},
): FakeLedger<keyof typeof ledgerRoutes.mfaWitness, "withdraw"> {
	const { withdraw: _, ...older } = ledgerRoutes.mfaWitness;
	const routes: typeof older & { readonly withdraw?: string } =
		options.withdraw === false ? older : ledgerRoutes.mfaWitness;
	const credential = randomBytes(32).toString("base64url");
	const kept = marksKept();
	return {
		credential,
		urls: (base) => at(routes, base),
		answer(call) {
			if (!ownCall(routes, call)) return undefined;
			if (!authorized(credential, call)) return { status: 404 };
			return witnessAnswer(routes, kept, call);
		},
	};
}

/** A fake ledger keeping the passkey witness: a read names the mark's token, and no clear is its call. */
export function passkeyWitnessLedger(): FakeLedger<keyof typeof ledgerRoutes.passkeyWitness> {
	const routes = ledgerRoutes.passkeyWitness;
	const credential = randomBytes(32).toString("base64url");
	const kept = marksKept();
	return {
		credential,
		urls: (base) => at(routes, base),
		answer(call) {
			if (!ownCall(routes, call)) return undefined;
			if (!authorized(credential, call)) return { status: 404 };
			return witnessAnswer(routes, kept, call);
		},
	};
}
