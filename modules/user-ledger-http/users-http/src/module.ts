import { deepFreeze, defineModule, setting } from "@mod/kernel";
import { outbound, outboundPolicy } from "@mod/outbound";
import { urlSetting } from "@mod/url-setting";
import { type Ledger, ledgers } from "@mod/users";
import { z } from "zod";
import { calls } from "./calls/calls.ts";

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

/** The ledger's URLs, each an operator's setting, by the key that names it. */
const urlKeys = ["verify-url", "subject-url"] as const;
const ledgerUrl = (what: string) =>
	urlSetting({ schemes: ["https", "http"] })
		.optional()
		.describe(`${what} Plain http is reached only where outbound's policy names it.`);

const section = z
	.strictObject({
		"verify-url": ledgerUrl("Where a password is verified; without it, no password matches."),
		"subject-url": ledgerUrl(
			"Where a user is looked up by subject; without it, every lookup by subject is unanswerable.",
		),
		credential: z
			.string()
			.regex(/^[A-Za-z0-9\-._~+/]+=*$/)
			.refine((token) => keyBytes(token) >= 32, "at least 32 bytes of key material")
			.optional()
			.describe("A bare bearer token (RFC 6750 b64token) of at least 32 bytes of key material."),
		timeout: setting
			.duration("ms")
			.pipe(z.number().int().min(1).max(60_000))
			.optional()
			.describe("How long a call may take, from 1ms to 1m, narrowing outbound's cap."),
		"max-response-size": setting
			.size()
			.pipe(z.number().int().min(1).max(16_777_216))
			.optional()
			.describe("The largest answer read, from 1B to 16MiB, narrowing outbound's cap."),
	})
	.superRefine((s, ctx) => {
		const urls = urlKeys.flatMap((key) => s[key] ?? []);
		if (urls.length === 0) {
			ctx.addIssue({ code: "custom", message: `needs one of ${urlKeys.join(", ")}` });
		}
		// The credential goes to one party alone.
		if (s.credential !== undefined && new Set(urls.map((url) => new URL(url).origin)).size > 1) {
			ctx.addIssue({
				code: "custom",
				path: ["credential"],
				message: "is sent to one origin alone, but the URLs name more than one",
			});
		}
	});

const unanswerable = deepFreeze({ kind: "unanswerable" } as const);
const none = deepFreeze({ kind: "none" } as const);

export default defineModule({ name: "users-http", section, replicaSafe: true }, (m) => [
	m.contribute(ledgers).by(async (c): Promise<Ledger> => {
		const { "max-response-size": maxBytes, timeout: timeoutMs } = c.section;
		// The operator's own URL: a host in `internal-hosts` is reached at a private address.
		const narrowerOf = (url: string) => ({
			hosts: [new URL(url).hostname],
			internal: true as const,
			...(maxBytes === undefined ? {} : { maxBytes }),
			...(timeoutMs === undefined ? {} : { timeoutMs }),
		});
		const policy = await c.get(outboundPolicy);
		for (const key of urlKeys) {
			const url = c.section[key];
			const refusal = url === undefined ? undefined : policy.refusalOf(url, narrowerOf(url));
			if (refusal !== undefined) {
				return c.refuse(
					`users-http.${key}`,
					`outbound's destination policy refuses it: ${refusal}`,
				);
			}
		}
		const ask = calls({
			out: await c.get(outbound),
			credential: c.section.credential,
			narrowerOf,
			warn: (event, fields) => c.log.warn(event, fields),
		});
		const { "verify-url": verifyUrl, "subject-url": subjectUrl } = c.section;
		return {
			verify: async (identifier, password) =>
				verifyUrl === undefined ? none : ask.verify(verifyUrl, identifier, password),
			bySubject: async (subject) =>
				subjectUrl === undefined ? unanswerable : ask.lookup(subjectUrl, { subject }),
		};
	}),
]);
