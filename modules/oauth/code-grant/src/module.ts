import { clientAllowance } from "@mod/client-allowance";
import { clients } from "@mod/clients";
import { grants, sessionIssuances } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule, Unavailable } from "@mod/kernel";
import { sessions } from "@mod/session";
import { tokens } from "@mod/tokens";
import { type CodeRecord, toStored } from "./codes.ts";
import {
	additions,
	challengeShape,
	codeGrantType,
	codeStore,
	codes,
	idTokens,
	redemptionHooks,
	sessionRedemptions,
	voidList,
} from "./contract.ts";
import { answerFields, codeGrant, voiding } from "./grant.ts";
import { section } from "./section.ts";

const takes = [
	codeStore,
	voidList,
	sessions,
	clients,
	issuer,
	tokens,
	idTokens,
	additions,
	sessionIssuances,
	sessionRedemptions,
	redemptionHooks,
];

// Safe on many instances: every instance runs the sweep over the shared void list, and settling a void twice
// does no harm (test/voids.test.ts).
export default defineModule({ name: "code-grant", replicaSafe: true, section, takes }, (m) => [
	m.provide(codes).by(async (c) => {
		const store = await c.get(codeStore);
		const opened = await c.get(sessions);
		const known = await c.get(clients);
		const issuerUrl = (await c.get(issuer)).url;
		const makers = await c.collect(idTokens);
		return {
			issue: async (facts) => {
				if (!challengeShape.test(facts.challenge)) throw new TypeError("code-grant: bad challenge");
				const entry = await opened.entryOf(facts.session);
				// One closed or short since the caller read it is no fault of the caller's: it answers as it can.
				if (entry.kind !== "entered") throw new Unavailable("code-grant");
				const context = entry.session.context;
				if (context.subject !== facts.subject)
					throw new TypeError("code-grant: not this session's subject");
				const client = await known.find(facts.clientId);
				if (
					!client ||
					!clientAllowance.allowsGrant(client, codeGrantType) ||
					!clientAllowance.covers(client, facts, issuerUrl)
				) {
					throw new TypeError("code-grant: outside the client's allowance");
				}
				const code = Buffer.from(c.random.bytes(32)).toString("base64url");
				const record: CodeRecord = {
					format: 2,
					state: "issued",
					...facts,
					amr: context.amr,
					authenticatedAt: context.authenticatedAt,
					...(context.authenticatedAtUnknown ? { authenticatedAtUnknown: true } : {}),
				};
				const saved = await store.save(
					store.nameOf(code),
					toStored(record),
					c.section["code-lifetime"] * 1000,
				);
				if (saved !== "created") throw new Unavailable("code-grant");
				return code;
			},
			redemptionOf: (code) => store.nameOf(code),
			lifetimeMs: () => c.section["code-lifetime"] * 1000,
			idTokenScope: () => (makers.length === 1 ? makers[0]?.scope : undefined),
		};
	}),
	m.contribute(grants).by(async (c) => {
		const issuing = await c.get(tokens);
		// A code that comes again must revoke what it gave; without a denylist it could not.
		if (!issuing.revocable()) {
			return c.refuse(
				"code-grant",
				"a configuration that cannot revoke access tokens cannot handle codes",
			);
		}
		// Its tokens are issued from the code's session: unrecorded, a logout could not end them.
		if ((await c.collect(sessionIssuances)).length === 0) {
			return c.refuse(
				"code-grant",
				"its tokens must be recorded to their session, so that a logout ends them",
			);
		}
		const makers = await c.collect(idTokens);
		if (makers.length > 1) return c.refuse("code-grant", "more than one ID token maker");
		const contributed = await c.collect(additions);
		const taken = contributed.find((a) => answerFields.has(a.field));
		if (taken) return c.refuse("code-grant", `the response field ${taken.field} already exists`);
		const store = await c.get(codeStore);
		const voids = voiding({
			store,
			voids: await c.get(voidList),
			tokens: issuing,
			log: c.log,
			now: c.clock.now,
			additions: contributed,
		});
		c.every(c.section["sweep-interval"] * 1000, () => voids.sweep());
		return codeGrant({
			store,
			sessions: await c.get(sessions),
			settle: voids.settle,
			now: c.clock.now,
			idToken: makers[0],
			additions: contributed,
			redemptions: await c.collect(sessionRedemptions),
			hooks: await c.collect(redemptionHooks),
		});
	}),
]);
