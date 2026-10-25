import { deepFreeze, defineModule, setting } from "@mod/kernel";
import { bearerToken } from "@mod/keys";
import { usersWire } from "@mod/ledger-wire";
import { outbound } from "@mod/outbound";
import {
	credentialPolicy,
	credentialRefusalText,
	destinationRefusal,
	outboundRefusals,
} from "@mod/outbound-policy";
import { type ConfiguredUrl, urlSetting } from "@mod/url-setting";
import { type Ledger, ledgers } from "@mod/users";
import { z } from "zod";
import { calls } from "./calls/calls.ts";

/** The ledger's URLs, each an operator's setting, by the key that names it. */
const urlKeys = ["verify-url", "subject-url", "upstream-url"] as const;
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
		"upstream-url": ledgerUrl(
			"Where a user is looked up by upstream identity; without it, users follows the links it keeps.",
		),
		credential: bearerToken({ atLeast: 32 })
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
	});

const unanswerable = deepFreeze({ kind: "unanswerable" } as const);
const none = deepFreeze({ kind: "none" } as const);

export default defineModule(
	{
		name: "users-http",
		section,
		replicaSafe: true,
		takes: [outbound, credentialPolicy, outboundRefusals],
	},
	(m) => [
		m.contribute(ledgers).by(async (c): Promise<Ledger> => {
			const { "max-response-size": maxBytes, timeout: timeoutMs } = c.section;
			// The operator's own URL: reached at a private address at its origin, for a host in
			// `internal-hosts` or, over plain http, a host:port `plain-internal` names.
			const narrowerOf = (url: ConfiguredUrl) => ({
				hosts: [new URL(url).hostname],
				internal: url,
				...(maxBytes === undefined ? {} : { maxBytes }),
				...(timeoutMs === undefined ? {} : { timeoutMs }),
			});
			const urls = urlKeys.flatMap((key) => c.section[key] ?? []);
			const refused =
				c.section.credential === undefined
					? undefined
					: (await c.get(credentialPolicy)).refusalOf(urls);
			// More than one origin first, as the section reads; a URL's own refusal is more precise than its scheme.
			if (refused === "origins")
				return c.refuse("users-http.credential", credentialRefusalText(refused));
			const refusals = await c.get(outboundRefusals);
			for (const key of urlKeys) {
				const url = c.section[key];
				const refused =
					url === undefined ? undefined : destinationRefusal(refusals, url, narrowerOf(url));
				if (refused !== undefined) return c.refuse(`users-http.${key}`, refused);
			}
			if (refused === "scheme")
				return c.refuse("users-http.credential", credentialRefusalText(refused));
			const ask = calls({
				out: await c.get(outbound),
				credential: c.section.credential,
				narrowerOf,
				warn: (event, fields) => c.log.warn(event, fields),
			});
			const {
				"verify-url": verifyUrl,
				"subject-url": subjectUrl,
				"upstream-url": upstreamUrl,
			} = c.section;
			return {
				verify: async (identifier, password) =>
					verifyUrl === undefined ? none : ask.verify(verifyUrl, identifier, password),
				bySubject: async (subject) =>
					subjectUrl === undefined
						? unanswerable
						: ask.lookup(subjectUrl, usersWire.bySubject(subject)),
				// Only a ledger asked by upstream identity answers it; users then reads no link of its own.
				...(upstreamUrl === undefined
					? {}
					: {
							byUpstream: async (idp: string, subject: string) =>
								ask.lookup(upstreamUrl, usersWire.byUpstream(idp, subject)),
						}),
			};
		}),
	],
);
