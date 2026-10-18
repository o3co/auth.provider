import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import { type GrantOutcome, sessionIssuances, targetRules } from "@mod/grants";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type FamilyHandle, type Lineage, lineage } from "@mod/refresh";
import { type Binding, senderBindings } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { stubSessions } from "@mod/session/testing";
import { sessionTokens } from "@mod/session-tokens";
import sessionTokensModule from "@mod/session-tokens/module";
import { sessionTokensInMemory } from "@mod/session-tokens/testing";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import {
	type AccessGrant,
	type IssuanceRequest,
	issuancePolicies,
	type Tokens,
	tokens,
} from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { describe, expect, it } from "vitest";
import { accessTokenType, type ExchangeVerifier, exchangeVerifiers } from "../src/contract.ts";
import tokenExchange from "../src/module.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256)) },
});
const grantType = "urn:ietf:params:oauth:grant-type:token-exchange";
const outsideType = "urn:example:outside";
const api = "https://api.example";
const admin = "https://admin.example";
const allowed = allowancesFor({
	grants: [grantType],
	scopes: ["read", "write"],
	audiences: [api, admin],
});

/**
 * Families and sessions in memory; `during` runs while a token is being recorded to a session.
 * Looser than refresh's lineage: `adopt` revokes nothing it refuses, and a family always ends 60 s on.
 */
function ties(during: () => void = () => {}) {
	const families = new Map<string, { ended: boolean }>();
	const memberOf = new Map<string, string>();
	const sessionOf = new Map<string, string>();
	const open = new Set<string>();
	const handle = (name: string) => name as unknown as FamilyHandle;
	const kept: Lineage = {
		of: async (id) => {
			const name = memberOf.get(id);
			if (name === undefined) return { kind: "none" };
			return families.get(name)?.ended
				? { kind: "ended" }
				: { kind: "family", family: handle(name), expiresAt: now + 60_000 };
		},
		adopt: async (family, issued) => {
			const name = family as unknown as string;
			if (families.get(name)?.ended) return "ended";
			memberOf.set(issued.id, name);
			return "adopted";
		},
		start: async () => undefined,
	};
	return {
		families,
		memberOf,
		sessionOf,
		open,
		module: defineModule({ name: "ties" }, (m) => [
			m.provide(lineage).by(() => kept),
			m.provide(sessions).by(() => stubSessions({ stillOpen: async (h) => open.has(h) })),
		]),
		/** session-tokens in memory, recording what token-endpoint tells it. */
		recording: defineModule({ name: "recording" }, (m) => [
			m.provide(sessionTokens).by(() => ({
				sessionOf: async (id) => {
					const session = sessionOf.get(id);
					return session === undefined ? { kind: "unbound" } : { kind: "bound", handle: session };
				},
			})),
			m.contribute(sessionIssuances).by(() => ({
				issued: async (session, issued) => {
					sessionOf.set(issued.id, session);
					during();
				},
			})),
		]),
	};
}

/** A verifier of another token type, answering what `answer` gives for each call. */
const outside = (answer: (call: number) => unknown): ExchangeVerifier => {
	let calls = 0;
	return { tokenType: outsideType, verify: async () => answer(++calls) as never };
};
const outsideAnswer = {
	subject: "erin",
	issuer: "https://idp.example",
	issuedTo: "app",
	audience: [api],
	scope: ["read"],
	expiresAt: now + 60_000,
};

/** A binding kind that writes `jkt`, so tokens bound by it verify. */
const dpopKind = defineModule({ name: "dpop-kind" }, (m) => [
	m
		.contribute(senderBindings)
		.by(() => ({ member: "jkt", tokenType: "DPoP", read: async () => ({ kind: "absent" }) })),
]);

async function serve(
	options: {
		tied?: ReturnType<typeof ties>;
		verifier?: ExchangeVerifier;
		settings?: object;
		extra?: Module[];
		/** In place of the tied session-tokens. */
		sessionTokens?: Module[];
	} = {},
) {
	const tied = options.tied ?? ties();
	const revoked: string[] = [];
	const standIn = tokensStandIn();
	// The stand-in, with every revocation noted.
	const watched = {
		...standIn,
		provides: (standIn.provides ?? []).map((part) => ({
			contract: part.contract,
			create: async (c: Parameters<typeof part.create>[0]) => {
				const given = (await part.create(c)) as Tokens;
				return {
					...given,
					revokeAccess: async (token: string) => {
						revoked.push(token);
						return given.revokeAccess(token);
					},
				};
			},
		})),
	};
	const verifier = options.verifier;
	const app = await assemble({
		modules: [
			http,
			watched,
			issuerModule,
			clientsModule,
			grantCaller,
			clientAllowanceModule,
			tied.module,
			...(options.sessionTokens ?? [tied.recording]),
			dpopKind,
			...(verifier
				? [
						defineModule({ name: "outside" }, (m) => [
							m.contribute(exchangeVerifiers).by(() => verifier),
						]),
					]
				: []),
			tokenExchange,
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...issuerConfig(),
			...clientsConfig([
				confidentialClient({ id: "app", sections: allowed }),
				confidentialClient({
					id: "gate",
					sections: { ...allowed, "token-exchange": { "others-tokens": true } },
				}),
				publicClient({ id: "spa", sections: allowed }),
			]),
			...(options.settings ? { "token-exchange": options.settings } : {}),
		},
		runtime,
	});
	const issuing = app.get(tokens);
	/** A subject token, as a code redeemed for the client would give it. */
	const issue = async (grant: Partial<AccessGrant> = {}, binding?: Binding) => {
		const issued = await issuing.issue(
			{
				grant: {
					subject: "alice",
					issuedTo: "app",
					audience: [api],
					scope: ["read", "write"],
					...grant,
				},
				grantType: "authorization_code",
			},
			binding ? { binding } : undefined,
		);
		if (issued.kind === "refused") throw new Error(issued.description);
		return issued.access;
	};
	/** Calls the grant as the endpoint does once it has read the binding the request proves. */
	const exchange = (as: string, params: Record<string, string>, binding?: Binding) =>
		app
			.get(grantCalls)
			.call(grantType, as, { grant_type: grantType, ...params }, binding ? { binding } : {});
	const issued = async (outcome: GrantOutcome) => {
		if (outcome.kind !== "issued") throw new Error(`${outcome.error}: ${outcome.description}`);
		const checked = await issuing.verifyAccess(String(outcome.body.access_token));
		if (checked.kind !== "valid") throw new Error(checked.reason);
		return checked;
	};
	return { app, tied, revoked, issuing, issue, exchange, issued };
}
const subjectOf = (token: string, type = accessTokenType) => ({
	subject_token: token,
	subject_token_type: type,
});
const said = (outcome: GrantOutcome) =>
	outcome.kind === "error" ? [outcome.error, outcome.description] : ["issued"];

describe("token-exchange", () => {
	it("issues an access token for the subject, narrowed to the scope asked, with no actor", async () => {
		const s = await serve();
		const outcome = await s.exchange("app", {
			...subjectOf((await s.issue()).token),
			scope: "read",
		});
		expect(outcome).toMatchObject({
			kind: "issued",
			body: { issued_token_type: accessTokenType, scope: "read" },
		});
		expect((await s.issued(outcome)).grant).toEqual({
			subject: "alice",
			issuedTo: "app",
			audience: [api],
			scope: ["read"],
		});
	});

	it("refuses a public client as unauthenticated, and anything but an access token", async () => {
		const s = await serve();
		const subject = subjectOf((await s.issue()).token);
		expect(await s.exchange("spa", subject)).toMatchObject({
			error: "invalid_client",
			status: 401,
		});
		const asked = await s.exchange("app", {
			...subject,
			requested_token_type: "urn:ietf:params:oauth:token-type:id_token",
		});
		expect(said(asked)).toEqual(["invalid_request", "requested_token_type is not supported"]);
	});

	it("takes a token naming another client only from a client whose section allows it", async () => {
		const s = await serve();
		const subject = subjectOf((await s.issue({ issuedTo: "elsewhere" })).token);
		expect(said(await s.exchange("app", subject))).toEqual([
			"invalid_request",
			"subject_token does not name this client",
		]);
		expect((await s.exchange("gate", subject)).kind).toBe("issued");
	});

	it("asks for the audience when the subject token holds two, and takes a resource only when it is that audience", async () => {
		const s = await serve();
		const subject = subjectOf((await s.issue({ audience: [api, admin] })).token);
		expect(said(await s.exchange("app", subject))).toEqual([
			"invalid_target",
			"audience is not one the subject token and the client hold",
		]);
		expect(
			(await s.issued(await s.exchange("app", { ...subject, audience: admin }))).grant.audience,
		).toEqual([admin]);
		expect(said(await s.exchange("app", { ...subject, audience: admin, resource: api }))).toEqual([
			"invalid_target",
			"resource is not the audience issued",
		]);
	});

	it("takes an actor only where the subject token's may_act names it", async () => {
		const mayAct = [{ sub: "app" }, { sub: "carol", iss: "https://idp.example" }];
		const s = await serve({ verifier: outside(() => ({ ...outsideAnswer, mayAct })) });
		const subject = subjectOf("outside", outsideType);
		expect((await s.issued(await s.exchange("app", subject))).grant.subject).toBe("erin");
		const actor = async (subject: string) => ({
			actor_token: (await s.issue({ subject })).token,
			actor_token_type: accessTokenType,
		});
		const refusal = said(await s.exchange("app", { ...subject, ...(await actor("carol")) }));
		expect(refusal).toEqual(["invalid_request", "may_act does not name the party acting"]);
	});

	it("refuses a chain longer than the operator's limit", async () => {
		const s = await serve({ settings: { "max-actor-depth": 2 } });
		const chained = await s.issue({ actor: { subject: "bob" } });
		const actor = {
			actor_token: (await s.issue({ subject: "carol" })).token,
			actor_token_type: accessTokenType,
		};
		const once = await s.issued(await s.exchange("app", { ...subjectOf(chained.token), ...actor }));
		expect(once.grant.actor).toEqual({ subject: "carol", actor: { subject: "bob" } });
		const twice = await s.issue({ actor: { subject: "dave", actor: { subject: "bob" } } });
		expect(said(await s.exchange("app", { ...subjectOf(twice.token), ...actor }))).toEqual([
			"invalid_request",
			"actor chain too deep",
		]);
	});

	it("allows a chain of three actors where the operator sets no limit, and no more", async () => {
		const s = await serve();
		const actor = {
			actor_token: (await s.issue({ subject: "carol" })).token,
			actor_token_type: accessTokenType,
		};
		const twice = await s.issue({ actor: { subject: "dave", actor: { subject: "bob" } } });
		const issued = await s.issued(await s.exchange("app", { ...subjectOf(twice.token), ...actor }));
		expect(issued.grant.actor?.actor?.actor).toEqual({ subject: "bob" });
		const thrice = await s.issue({
			actor: { subject: "erin", actor: { subject: "dave", actor: { subject: "bob" } } },
		});
		expect(said(await s.exchange("app", { ...subjectOf(thrice.token), ...actor }))).toEqual([
			"invalid_request",
			"actor chain too deep",
		]);
	});
});

describe("token-exchange: refusals", () => {
	it("answers each request or token it cannot meet with its own refusal", async () => {
		const s = await serve({
			verifier: outside(() => ({ ...outsideAnswer, expiresAt: now + 500 })),
		});
		const own = (await s.issue()).token;
		const cases: Record<string, [Record<string, string>, string[]]> = {
			"a token type no verifier reads": [
				subjectOf(own, "urn:example:other"),
				["invalid_request", "subject_token_type is not supported"],
			],
			"a token ending within the second": [
				subjectOf("outside", outsideType),
				["invalid_request", "subject_token has expired"],
			],
			"a scope outside the subject token's and the client's": [
				{ ...subjectOf(own), scope: "read admin" },
				["invalid_scope", "scope is not within the subject token's and the client's"],
			],
			"an actor token without its type": [
				{ ...subjectOf(own), actor_token: own },
				["invalid_request", "actor_token and actor_token_type go together"],
			],
		};
		for (const [name, [params, answer]] of Object.entries(cases)) {
			expect(said(await s.exchange("app", params)), name).toEqual(answer);
		}
	});

	it("reads its own resource where a rule refuses one to a grant that takes no audience", async () => {
		const strict = defineModule({ name: "strict" }, (m) => [
			m.contribute(targetRules).by(() => ({
				target: ({ audience }) => ({ kind: "audience", audience }),
				untargeted: ({ param }) =>
					param("resource")
						? { kind: "error", error: "invalid_target", description: "takes no resource" }
						: undefined,
			})),
		]);
		const s = await serve({ extra: [strict] });
		const subject = subjectOf((await s.issue()).token);
		expect(await s.exchange("app", { ...subject, resource: api })).toMatchObject({
			kind: "issued",
		});
	});

	it("issues a scope asked twice once", async () => {
		const s = await serve();
		const outcome = await s.exchange("app", {
			...subjectOf((await s.issue()).token),
			scope: "read read",
		});
		expect((await s.issued(outcome)).grant.scope).toEqual(["read"]);
	});
});

describe("token-exchange: bindings", () => {
	const keyOf = (confirmation: string): Binding => ({
		member: "jkt",
		confirmation,
		tokenType: "DPoP",
	});
	const unbound = "the request does not prove the binding of the tokens presented";

	it("refuses a bound subject token when the request proves no key", async () => {
		const s = await serve();
		const subject = subjectOf((await s.issue({}, keyOf("k1"))).token);
		expect(said(await s.exchange("app", subject))).toEqual(["invalid_request", unbound]);
	});

	it("issues for a bound subject token when the request proves the same key, bound to that key", async () => {
		const s = await serve();
		const subject = subjectOf((await s.issue({}, keyOf("k1"))).token);
		const issued = await s.issued(await s.exchange("app", subject, keyOf("k1")));
		expect(issued.binding).toEqual(keyOf("k1"));
	});

	it("binds the token issued for an unbound subject token to the key the request proves", async () => {
		const s = await serve();
		const subject = subjectOf((await s.issue()).token);
		const issued = await s.issued(await s.exchange("app", subject, keyOf("k1")));
		expect(issued.binding).toEqual(keyOf("k1"));
	});

	it("refuses a subject token and an actor token bound to different keys", async () => {
		const s = await serve();
		const subject = subjectOf((await s.issue({}, keyOf("k1"))).token);
		const actor = {
			actor_token: (await s.issue({ subject: "carol" }, keyOf("k2"))).token,
			actor_token_type: accessTokenType,
		};
		const outcome = await s.exchange("app", { ...subject, ...actor }, keyOf("k1"));
		expect(said(outcome)).toEqual(["invalid_request", unbound]);
	});
});

describe("token-exchange: a verifier's answer", () => {
	it("refuses a second verifier for the same token type at boot", async () => {
		const twin: ExchangeVerifier = {
			tokenType: accessTokenType,
			verify: async () => ({ kind: "invalid" }),
		};
		await expect(serve({ verifier: twin })).rejects.toThrow(BootRefused);
	});

	it("counts an answer whose scope holds other than single scope tokens as a failed validation", async () => {
		for (const scope of [[""], ["read write"], ['re"ad']]) {
			const s = await serve({ verifier: outside(() => ({ ...outsideAnswer, scope })) });
			expect(said(await s.exchange("app", subjectOf("outside", outsideType))), scope[0]).toEqual([
				"invalid_request",
				"subject_token validation failed",
			]);
		}
	});

	it("counts a malformed answer as a failed validation, never skipping the family", async () => {
		const malformed = await serve({ verifier: outside(() => ({ ...outsideAnswer, issued: 42 })) });
		const refusal = said(await malformed.exchange("app", subjectOf("outside", outsideType)));
		expect(refusal).toEqual(["invalid_request", "subject_token validation failed"]);
		const named = await serve();
		const own = await named.issue();
		named.tied.families.set("f", { ended: true });
		named.tied.memberOf.set(own.id, "f");
		expect(said(await named.exchange("app", subjectOf(own.token)))).toEqual([
			"invalid_request",
			"subject_token family has ended",
		]);
	});

	it("looks up a family and a session for its own tokens only, never for another verifier's", async () => {
		const tied = ties();
		tied.families.set("f", { ended: true });
		tied.memberOf.set("x", "f");
		tied.sessionOf.set("y", "closed");
		const family = await serve({
			tied,
			verifier: outside(() => ({ ...outsideAnswer, issued: "x" })),
		});
		const adopted = await family.issued(
			await family.exchange("app", subjectOf("outside", outsideType)),
		);
		expect(tied.memberOf.get(adopted.id)).toBeUndefined();
		const session = await serve({
			tied,
			verifier: outside(() => ({ ...outsideAnswer, issued: "y" })),
		});
		const recorded = await session.issued(
			await session.exchange("app", subjectOf("outside", outsideType)),
		);
		expect(tied.sessionOf.get(recorded.id)).toBeUndefined();
	});

	it("reads an answer that says invalid as invalid, whatever else it holds", async () => {
		const s = await serve({ verifier: outside(() => ({ ...outsideAnswer, kind: "invalid" })) });
		expect(said(await s.exchange("app", subjectOf("outside", outsideType)))).toEqual([
			"invalid_request",
			"subject_token validation failed",
		]);
	});

	it("reads an answer once, so a value that changes later is not what it issues for", async () => {
		let reads = 0;
		const shifting = { ...outsideAnswer };
		Object.defineProperty(shifting, "subject", {
			enumerable: true,
			get: () => (reads++ === 0 ? "erin" : "mallory"),
		});
		const s = await serve({ verifier: outside((call) => (call === 1 ? shifting : outsideAnswer)) });
		expect(
			(await s.issued(await s.exchange("app", subjectOf("outside", outsideType)))).grant.subject,
		).toBe("erin");
	});

	it("carries amr, the authentication time and acr from its own tokens only", async () => {
		const context = { amr: ["hwk"], authenticatedAt: now - 5000, acr: "urn:example:acr:high" };
		const s = await serve({ verifier: outside(() => ({ ...outsideAnswer, ...context })) });
		const own = await s.issue({
			amr: ["pwd"],
			authenticatedAt: now - 9000,
			acr: "urn:example:acr:mfa",
		});
		expect((await s.issued(await s.exchange("app", subjectOf(own.token)))).grant).toMatchObject({
			amr: ["pwd"],
			authenticatedAt: now - 9000,
			acr: "urn:example:acr:mfa",
		});
		const theirs = (await s.issued(await s.exchange("app", subjectOf("outside", outsideType))))
			.grant;
		expect([theirs.amr, theirs.authenticatedAt, theirs.acr]).toEqual([
			undefined,
			undefined,
			undefined,
		]);
	});

	it("issues through the issuance policies, refusing as they say", async () => {
		const asked: IssuanceRequest[] = [];
		const refusing = defineModule({ name: "refusing" }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					// The subject token's own issuance is let through.
					if (request.grantType !== grantType) return { kind: "allowed" };
					asked.push(request);
					return { kind: "refused", reason: "test_reason", description: "refused here" };
				},
			})),
		]);
		const s = await serve({ extra: [refusing] });
		const own = await s.issue();
		expect(said(await s.exchange("app", subjectOf(own.token)))).toEqual([
			"invalid_grant",
			"refused here",
		]);
		expect(asked.map(({ grantType, session }) => [grantType, session])).toEqual([
			[grantType, undefined],
		]);
		expect(s.revoked).toEqual([]);
	});

	it("tells the issuance policies the session the subject token was issued in", async () => {
		const asked: IssuanceRequest[] = [];
		const watching = defineModule({ name: "watching" }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					if (request.grantType === grantType) asked.push(request);
					return { kind: "allowed" };
				},
			})),
		]);
		const s = await serve({ extra: [watching] });
		const own = await s.issue();
		s.tied.open.add("h");
		s.tied.sessionOf.set(own.id, "h");
		await s.issued(await s.exchange("app", subjectOf(own.token)));
		expect(asked.map(({ session }) => session)).toEqual(["h"]);
	});

	it("tells them the session of a subject token that is in a family too, and refuses one whose session ended", async () => {
		const asked: IssuanceRequest[] = [];
		const watching = defineModule({ name: "watching" }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					if (request.grantType === grantType) asked.push(request);
					return { kind: "allowed" };
				},
			})),
		]);
		const s = await serve({ extra: [watching] });
		const own = await s.issue();
		s.tied.families.set("f", { ended: false });
		s.tied.memberOf.set(own.id, "f");
		s.tied.open.add("h");
		s.tied.sessionOf.set(own.id, "h");
		const issued = await s.issued(await s.exchange("app", subjectOf(own.token)));
		expect(asked.map(({ session }) => session)).toEqual(["h"]);
		expect([s.tied.memberOf.get(issued.id), s.tied.sessionOf.get(issued.id)]).toEqual(["f", "h"]);
		s.tied.open.delete("h");
		expect(await s.exchange("app", subjectOf(own.token))).toMatchObject({
			error: "invalid_request",
			description: "subject_token session has ended",
		});
	});
});

describe("token-exchange: how the issued token ends", () => {
	it("adopts it into the subject's family, and records it to the subject's session when there is no family", async () => {
		const s = await serve();
		const family = await s.issue();
		s.tied.families.set("f", { ended: false });
		s.tied.memberOf.set(family.id, "f");
		const adopted = await s.issued(await s.exchange("app", subjectOf(family.token)));
		expect(s.tied.memberOf.get(adopted.id)).toBe("f");
		const session = await s.issue();
		s.tied.open.add("h");
		s.tied.sessionOf.set(session.id, "h");
		const recorded = await s.issued(await s.exchange("app", subjectOf(session.token)));
		expect(s.tied.sessionOf.get(recorded.id)).toBe("h");
		s.tied.open.delete("h");
		expect(said(await s.exchange("app", subjectOf(session.token)))).toEqual([
			"invalid_request",
			"subject_token session has ended",
		]);
	});

	it("has a token from a recorded subject token recorded to its session, as session-tokens answers it", async () => {
		const inMemory = sessionTokensInMemory();
		const s = await serve({ sessionTokens: [sessionTokensModule, inMemory.module] });
		const subject = await s.issue();
		s.tied.open.add("h");
		// Indexed as session-tokens indexes a token issued from a session.
		await inMemory.index.save(subject.id, "h", 60_000);
		const issued = await s.issued(await s.exchange("app", subjectOf(subject.token)));
		expect(await s.app.get(sessionTokens).sessionOf(issued.id)).toEqual({
			kind: "bound",
			handle: "h",
		});
	});

	it("passes on a failure to record the token to the session, which is revoked", async () => {
		const tied = ties(() => {
			throw new Unavailable("session-tokens");
		});
		const s = await serve({ tied });
		const subject = await s.issue();
		tied.open.add("h");
		tied.sessionOf.set(subject.id, "h");
		await expect(s.exchange("app", subjectOf(subject.token))).rejects.toThrow(Unavailable);
		const told = [...tied.sessionOf.keys()].filter((id) => id !== subject.id);
		expect(told).toHaveLength(1);
		expect(await s.issuing.verifyAccess(`stand-in.${told[0]}`)).toMatchObject({
			reason: "revoked",
		});
	});

	it("revokes what it issued and refuses when the session closes while the token is recorded", async () => {
		const tied = ties(() => tied.open.delete("h"));
		const s = await serve({ tied });
		const session = await s.issue();
		tied.open.add("h");
		tied.sessionOf.set(session.id, "h");
		expect(said(await s.exchange("app", subjectOf(session.token)))).toEqual([
			"invalid_request",
			"subject_token has ended",
		]);
		expect(s.revoked).toHaveLength(1);
		expect(await s.issuing.verifyAccess(s.revoked[0] ?? "")).toMatchObject({ reason: "revoked" });
	});

	it("checks the tokens again right before issuing", async () => {
		const s = await serve({
			verifier: outside((call) => (call === 1 ? outsideAnswer : { kind: "invalid" })),
		});
		expect(said(await s.exchange("app", subjectOf("outside", outsideType)))).toEqual([
			"invalid_request",
			"subject_token validation failed",
		]);
	});
});

describe("token-exchange: the lifetime asked", () => {
	const lifetimeOf = (outcome: GrantOutcome) =>
		outcome.kind === "issued" ? outcome.body.expires_in : said(outcome);

	it("issues for a shorter expires_in, and for the usual lifetime when it is left out or empty", async () => {
		const s = await serve();
		const subject = subjectOf((await s.issue()).token);
		const shorter = await s.exchange("app", { ...subject, expires_in: "60" });
		expect(lifetimeOf(shorter)).toBe(60);
		expect((await s.issued(shorter)).expiresAt).toBe(Math.floor(now / 1000) * 1000 + 60_000);
		expect(lifetimeOf(await s.exchange("app", subject))).toBe(3600);
		expect(lifetimeOf(await s.exchange("app", { ...subject, expires_in: "" }))).toBe(3600);
	});

	it("cuts a longer expires_in to the operator's cap, and to the subject token's expiry", async () => {
		const s = await serve({ settings: { "max-lifetime": "10m" } });
		const subject = subjectOf((await s.issue()).token);
		expect(lifetimeOf(await s.exchange("app", { ...subject, expires_in: "7200" }))).toBe(600);
		expect(lifetimeOf(await s.exchange("app", { ...subject, expires_in: "9999999999" }))).toBe(600);
		expect(lifetimeOf(await s.exchange("app", subject))).toBe(600);
		const uncapped = await serve();
		const own = subjectOf((await uncapped.issue()).token);
		expect(lifetimeOf(await uncapped.exchange("app", { ...own, expires_in: "7200" }))).toBe(3600);
		const short = await serve({ verifier: outside(() => outsideAnswer) });
		const outsider = { ...subjectOf("outside", outsideType), expires_in: "600" };
		expect(lifetimeOf(await short.exchange("app", outsider))).toBe(60);
	});

	it("lets a cap above tokens' lifetime extend the lifetime asked, never one left out", async () => {
		const lasting = outside(() => ({ ...outsideAnswer, expiresAt: now + 86_400_000 }));
		const s = await serve({ verifier: lasting, settings: { "max-lifetime": "2h" } });
		const subject = subjectOf("outside", outsideType);
		expect(lifetimeOf(await s.exchange("app", { ...subject, expires_in: "5400" }))).toBe(5400);
		expect(lifetimeOf(await s.exchange("app", { ...subject, expires_in: "9000" }))).toBe(7200);
		expect(lifetimeOf(await s.exchange("app", subject))).toBe(3600);
	});

	it("refuses an expires_in that is not a positive whole number of seconds, before the tokens", async () => {
		const s = await serve();
		const subject = subjectOf((await s.issue()).token);
		const malformed = [
			"invalid_request",
			"expires_in must be a positive whole number of seconds in ASCII digits",
		];
		for (const value of ["abc", "0", "-60", "1.5", "1e3", " 60", "+60", "12345678901"]) {
			expect(said(await s.exchange("app", { ...subject, expires_in: value }))).toEqual(malformed);
		}
		const forged = subjectOf("forged");
		expect(said(await s.exchange("app", { ...forged, expires_in: "0" }))).toEqual(malformed);
	});

	it("refuses a cap that is not a whole number of seconds within a day, names no unit, or goes by its name in seconds, at boot", async () => {
		for (const cap of ["0s", "86401s", "1500ms", "600x", 600, "600"]) {
			await expect(serve({ settings: { "max-lifetime": cap } })).rejects.toThrow(BootRefused);
		}
		await expect(serve({ settings: { "max-lifetime-seconds": 600 } })).rejects.toThrow(BootRefused);
	});
});
