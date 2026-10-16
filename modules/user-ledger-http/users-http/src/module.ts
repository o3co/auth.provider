import { deepFreeze, defineModule, Unavailable } from "@mod/kernel";
import {
	DestinationRefused,
	jsonObjectOf,
	OutboundUnavailable,
	outbound,
	outboundPolicy,
} from "@mod/outbound";
import { urlSetting } from "@mod/url-setting";
import {
	isWellFormedSubject,
	type Ledger,
	ledgers,
	userAttribute,
	type Verified,
} from "@mod/users";
import { z } from "zod";

/** The fewest bytes of key material a token can be read as: its own, or as hex or base64 decodes them. */
function keyBytes(token: string): number {
	const hex = /^(?:[0-9a-fA-F]{2})+$/.test(token) ? token.length / 2 : undefined;
	const body = token.replace(/=+$/, "");
	const padding = token.length - body.length;
	// Base64 as written: one alphabet, no lone sixth bit, and padding that completes the last four.
	const alphabet = /^[A-Za-z0-9+/]+$/.test(body) || /^[A-Za-z0-9_-]+$/.test(body);
	const rest = body.length % 4;
	const base64 =
		alphabet && padding <= 2 && rest !== 1 && (padding === 0 || rest + padding === 4)
			? Math.floor((body.length * 3) / 4)
			: undefined;
	return Math.min(...[Buffer.byteLength(token), hex, base64].filter((n) => n !== undefined));
}

const section = z.strictObject({
	/** Where a password is verified. Plain http is reached only where outbound's policy names it. */
	"verify-url": urlSetting({ schemes: ["https", "http"] }),
	/** A bare bearer token (RFC 6750 b64token) of at least 32 bytes of key material. */
	credential: z
		.string()
		.regex(/^[A-Za-z0-9\-._~+/]+=*$/)
		.refine((token) => keyBytes(token) >= 32, "at least 32 bytes of key material")
		.optional(),
	"timeout-ms": z.number().int().min(1).max(60_000).optional(),
	"max-response-bytes": z.number().int().min(1).max(16_777_216).optional(),
});

const none: Verified = deepFreeze({ kind: "none" });
/** The ledger's fields kept as given, each with users' name for it. */
const keptFields = [
	["email", userAttribute.email],
	["name", userAttribute.name],
	["picture", userAttribute.picture],
	["groups", userAttribute.groups],
] as const;
const isName = (value: unknown): value is string => typeof value === "string" && value !== "";
const unanswerable = deepFreeze({ kind: "unanswerable" } as const);

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

/** The ledger's request: the identifier under the name the HTTP user repository reads, and the password. */
const requestOf = (identifier: string, password: string) =>
	JSON.stringify({ email: identifier, password });

/** The ledger's user `{id, username, ...}` as a new frozen user, or undefined when it is not one. */
function userOf(answer: Readonly<Record<string, unknown>>) {
	const { id, username, emailVerified } = answer;
	if (!isWellFormedSubject(id) || !isName(username)) return undefined;
	const attributes = Object.fromEntries([
		...keptFields.filter(([field]) => Object.hasOwn(answer, field)).map(([f, a]) => [a, answer[f]]),
		// Only a boolean says whether the email is verified, and only beside the email it is about.
		...(typeof emailVerified === "boolean" && Object.hasOwn(answer, "email")
			? [[userAttribute.emailVerified, emailVerified]]
			: []),
	]);
	return deepFreeze({ kind: "user", user: { subject: id, attributes } } as const);
}

export default defineModule({ name: "users-http", section, replicaSafe: true }, (m) => [
	m.contribute(ledgers).by(async (c): Promise<Ledger> => {
		const {
			"verify-url": url,
			credential,
			"max-response-bytes": maxBytes,
			"timeout-ms": timeoutMs,
		} = c.section;
		// The operator's own URL: a host in `internal-hosts` is reached at a private address.
		const narrower = {
			hosts: [new URL(url).hostname],
			internal: true as const,
			...(maxBytes === undefined ? {} : { maxBytes }),
			...(timeoutMs === undefined ? {} : { timeoutMs }),
		};
		const refusal = (await c.get(outboundPolicy)).refusalOf(url, narrower);
		if (refusal !== undefined) {
			return c.refuse(
				"users-http.verify-url",
				`outbound's destination policy refuses it: ${refusal}`,
			);
		}
		const out = await c.get(outbound);
		/** Logs why the ledger failed, by its kind or status alone, and answers unavailable. */
		const failed = (why: { reason: string } | { status: number }) => {
			c.log.warn("users-http.ledger_failed", why);
			return new Unavailable("users-http");
		};
		const verify = async (identifier: string, password: string): Promise<Verified> => {
			const headers = {
				accept: "application/json",
				"content-type": "application/json",
				...(credential === undefined ? {} : { authorization: `Bearer ${credential}` }),
			};
			const body = requestOf(identifier, password);
			const answer = await out
				.fetch(url, { method: "POST", headers, body }, narrower)
				.catch((error: unknown) => {
					throw failed({ reason: kindOf(error) });
				});
			if (answer.status === 401 || answer.status === 403) {
				// A challenge refuses the credential; with none sent, it can only refuse the user.
				const challenged = challengesBearer(answer.headers.get("www-authenticate"));
				if (credential === undefined || !challenged) return none;
				throw failed({ reason: "credential-refused" });
			}
			if (answer.status !== 200) throw failed({ status: answer.status });
			const read = jsonObjectOf(answer);
			const user = read.kind === "object" ? userOf(read.value) : undefined;
			if (!user) throw failed({ reason: "malformed" });
			return user;
		};
		// The ledger offers no lookup by subject.
		return { verify, bySubject: async () => unanswerable };
	}),
]);
