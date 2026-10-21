import { deepFreeze, type LogFields, Unavailable } from "@mod/kernel";
import {
	DestinationRefused,
	jsonObjectOf,
	type Narrower,
	type Outbound,
	type OutboundResponse,
	OutboundUnavailable,
} from "@mod/outbound";
import type { ConfiguredUrl } from "@mod/url-setting";
import { isWellFormedSubject, userAttribute, type Verified } from "@mod/users";

/** What the calls are made with: outbound, the credential if any, the narrower of each URL, and the log. */
export interface CallParts {
	readonly out: Outbound;
	readonly credential: string | undefined;
	readonly narrowerOf: (url: ConfiguredUrl) => Narrower;
	readonly warn: (event: string, fields: LogFields) => void;
}

/** The ledger's calls: the password call, and a lookup that posts what it looks up. */
export interface Calls {
	verify(url: ConfiguredUrl, identifier: string, password: string): Promise<Verified>;
	lookup(url: ConfiguredUrl, asked: Readonly<Record<string, string>>): Promise<Verified>;
}

const none: Verified = deepFreeze({ kind: "none" });
/** What a lookup's 404 and 410 must say in their body to mean no such user. */
const noneSaid: Readonly<Record<number, string>> = { 404: "not_found", 410: "gone" };
/** The ledger's fields kept as given, each with users' name for it. */
const keptFields = [
	["email", userAttribute.email],
	["name", userAttribute.name],
	["picture", userAttribute.picture],
	["groups", userAttribute.groups],
] as const;
const isName = (value: unknown): value is string => typeof value === "string" && value !== "";

/** Whether a WWW-Authenticate value names the Bearer scheme; a quoted string is read as empty. */
function challengesBearer(value: string | undefined): boolean {
	if (value === undefined) return false;
	const unquoted = value.replace(/"(?:[^"\\]|\\[\s\S])*"?/g, '""');
	// After the scheme: the end, a comma, or a space then token68 or parameters; `bearer=` is a
	// parameter of another scheme (RFC 9110 §11.6.1).
	return /(?:^|,)[ \t]*bearer(?:[ \t]*(?:,|$)|[ \t]+(?![ \t=]))/i.test(unquoted);
}

/** The kind outbound gives a failure to send, or no-answer for anything else. */
function kindOf(error: unknown): string {
	if (error instanceof DestinationRefused) return error.reason;
	if (error instanceof OutboundUnavailable) return error.failure;
	return "no-answer";
}

/** The ledger's user `{id, ...}` as a new frozen user, or undefined when it is not one. */
function userOf(answer: Readonly<Record<string, unknown>>) {
	const { id, emailVerified } = answer;
	if (!isWellFormedSubject(id)) return undefined;
	const attributes = Object.fromEntries([
		...keptFields.filter(([field]) => Object.hasOwn(answer, field)).map(([f, a]) => [a, answer[f]]),
		// Only a boolean says whether the email is verified, and only beside the email it is about.
		...(typeof emailVerified === "boolean" && Object.hasOwn(answer, "email")
			? [[userAttribute.emailVerified, emailVerified]]
			: []),
	]);
	return deepFreeze({ kind: "user", user: { subject: id, attributes } } as const);
}

export function calls(parts: CallParts): Calls {
	const { out, credential, narrowerOf, warn } = parts;
	/** Logs why the ledger failed, by its kind or status alone, and answers unavailable. */
	const failed = (why: { reason: string } | { status: number; reason?: string }) => {
		warn("users-http.ledger_failed", why);
		return new Unavailable("users-http");
	};
	const headers = deepFreeze({ accept: "application/json", "content-type": "application/json" });
	const sent = credential === undefined ? {} : { credential: `Bearer ${credential}` };
	const post = (url: ConfiguredUrl, body: unknown) =>
		out
			.fetch(url, { method: "POST", headers, body: JSON.stringify(body), ...sent }, narrowerOf(url))
			.catch((error: unknown) => {
				throw failed({ reason: kindOf(error) });
			});
	/** A `200` read once into a user, or unavailable. */
	const userIn = (answer: OutboundResponse, wanted: (user: object) => boolean) => {
		if (answer.status !== 200) throw failed({ status: answer.status });
		const read = jsonObjectOf(answer);
		const user = read.kind === "object" && wanted(read.value) ? userOf(read.value) : undefined;
		if (!user) throw failed({ reason: "malformed" });
		return user;
	};
	return {
		async verify(url, identifier, password) {
			// The identifier under the name the ledger's password call reads.
			const answer = await post(url, { email: identifier, password });
			// A 401 alone refuses the user: a 403 may come from a proxy before the ledger while it fails, and
			// read as a wrong password it would hold the account's logins back.
			if (answer.status === 401) {
				// A challenge refuses the credential; with none sent, it can only refuse the user.
				const challenged = challengesBearer(answer.headers.get("www-authenticate"));
				if (credential === undefined || !challenged) return none;
				throw failed({ reason: "credential-refused" });
			}
			return userIn(answer, (user) => isName((user as { username?: unknown }).username));
		},
		async lookup(url, asked) {
			const answer = await post(url, asked);
			// Not known, or known and refused, only where the ledger says so: a bare 404 may be a wrong
			// path, a gateway or a ledger hiding itself, never no such user.
			const said = noneSaid[answer.status];
			if (said !== undefined) {
				const read = jsonObjectOf(answer, answer.status);
				if (read.kind === "object" && read.value.error === said) return none;
				throw failed({ status: answer.status, reason: "unmarked" });
			}
			return userIn(answer, () => true);
		},
	};
}
