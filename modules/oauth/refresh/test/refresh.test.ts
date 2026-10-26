import { createHash, randomBytes } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { type Client, clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import {
	clientSecret,
	clientsConfig,
	confidentialClient,
	publicClient,
} from "@mod/clients/testing";
import { additions, codes } from "@mod/code-grant";
import codeGrantModule from "@mod/code-grant/module";
import { codeGrantConfig } from "@mod/code-grant/testing";
import codeGrantStore from "@mod/code-grant-store/module";
import { grants, targetRules, tokenTies } from "@mod/grants";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	contract,
	defineModule,
	type ExtensionPoint,
	isUnavailable,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, switchedModule, takesUnused, unavailableSwitch } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import sessionParticipants from "@mod/session-participants/module";
import { entryRequirements } from "@mod/session-requirements";
import sessionRequirements from "@mod/session-requirements/module";
import { sessionTokens } from "@mod/session-tokens";
import sessionTokensModule from "@mod/session-tokens/module";
import { sessionTokensInMemory } from "@mod/session-tokens/testing";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocation } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { revocableKinds } from "@mod/token-control";
import tokenControl from "@mod/token-control/module";
import { grantCaller, grantCalls, grantInput } from "@mod/token-endpoint/testing";
import tokenExchange from "@mod/token-exchange/module";
import {
	type AccessGrant,
	type IssueLimits,
	issuancePolicies,
	type Tokens,
	tokens,
} from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, describe, expect, it, vi } from "vitest";
import { lineage } from "../src/contract.ts";
import refreshModule from "../src/module.ts";
import { toStored, toStoredRedemption } from "../src/record.ts";
import { section } from "../src/section.ts";
import { refreshConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

/** How far the composition's clock runs ahead of the host's. */
let shift = 0;
/** Bytes the next draw of 16 takes, so a test can know the name of the next family. */
let forced: Uint8Array | undefined;
const runtime = quietRuntime({
	clock: { now: () => Date.now() + shift },
	random: {
		bytes: (n) => {
			const next = n === 16 ? forced : undefined;
			if (next) forced = undefined;
			return next ?? new Uint8Array(randomBytes(n));
		},
	},
});
let stop = async () => {};
afterEach(async () => {
	vi.useRealTimers();
	shift = 0;
	forced = undefined;
	await stop();
});
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const exchangeType = "urn:ietf:params:oauth:grant-type:token-exchange";
const allowed = (grants: string[]) =>
	allowancesFor({ grants, scopes: ["read", "write"], audiences: ["https://api"] });
/** What modules contribute to `point`, read back after assembly. */
function collecting<T>(name: string, point: ExtensionPoint<T>) {
	const seen = contract<readonly T[]>(name);
	return {
		seen,
		module: defineModule({ name, takes: [point] }, (m) => [
			m.provide(seen).by((c) => c.collect(point)),
		]),
	};
}
const grantsSeen = collecting("grants-seen", grants);
const tiesSeen = collecting("ties-seen", tokenTies);
/** The family name a refresh token carries before its dot. */
const familyNameOf = (token: string | undefined) => (token ?? "").split(".")[0] ?? "";
/** An access token issued as a code redemption issues it, under the issuance policies. */
const issuedAccess = async (t: Tokens, grant: AccessGrant, limits?: IssueLimits) => {
	const issued = await t.issue({ grant, grantType: "authorization_code" }, limits);
	if (issued.kind !== "issued") throw new Error(issued.reason);
	return issued.access;
};
type Options = {
	revocation?: "denylist" | "unsupported";
	lifetime?: number;
	/** An access token's own lifetime, in seconds, when not tokens' default. */
	accessLifetime?: number;
	/** Whether a confidential client's families are bound too. */
	bindConfidential?: boolean;
	extra?: Module[];
	caps?: { sessionFamilies: number; issuedAccess: number };
};

/** What `serve` assembles, with the stand-ins it reaches into. */
function assembly(options: Options = {}) {
	const simulated = simulatedStore();
	const audited = auditStandIn();
	const stores = memoryStores(options.caps);
	const down = { tokens: unavailableSwitch<Tokens>("tokens") };
	const both = ["authorization_code", "refresh_token"];
	const input = {
		modules: [
			http,
			switchedModule(
				tokensStandIn({
					revocable: (options.revocation ?? "denylist") === "denylist",
					...(options.accessLifetime ? { lifetimeSeconds: options.accessLifetime } : {}),
				}),
				tokens,
				down.tokens,
			),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			tokenControl,
			rateLimitStandIn,
			audited.module,
			sessionStandIn,
			sessionRequirements,
			sessionParticipants,
			subjectRevocationStandIn,
			simulated.module,
			sessionTokensModule,
			sessionTokensInMemory().module,
			codeGrantModule,
			codeGrantStore,
			refreshModule,
			stores.module,
			grantsSeen.module,
			tiesSeen.module,
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...issuerConfig({ url: "https://as.example" }),
			...clientsConfig([
				confidentialClient({ id: "app", sections: allowed(both) }),
				confidentialClient({ id: "other", sections: allowed(both) }),
				confidentialClient({ id: "coded", sections: allowed(["authorization_code"]) }),
				publicClient({ id: "pub", sections: allowed(both) }),
				confidentialClient({ id: "exchanger", sections: allowed([...both, exchangeType]) }),
			]),
			...codeGrantConfig(),
			...refreshConfig({
				lifetime: `${options.lifetime ?? 3600}s`,
				"sweep-interval": "1s",
				...(options.bindConfidential ? { "bind-confidential-clients": true } : {}),
			}),
		},
		runtime,
	};
	return { input, audited, stores, down };
}

async function serve(options: Options = {}) {
	const { input, audited, stores, down } = assembly(options);
	const app = await assemble(input);
	await app.start();
	stop = () => app.stop(1000);
	const { session } = await app.get(sessions).complete(testRequest(), {
		subject: "alice",
		amr: ["pwd"],
		authenticatedAt: runtime.clock.now(),
	});
	const post = async (path: string, as: string, form: Record<string, string>) => {
		const credentials: Record<string, string> =
			as === "pub" ? { client_id: as } : { client_id: as, client_secret: clientSecret(as) };
		const res = await fetch(`http://127.0.0.1:${app.get(listening).port()}${path}`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ ...form, ...credentials }),
		});
		return {
			status: res.status,
			body: (await res.json().catch(() => ({}))) as Record<string, string>,
		};
	};
	/**
	 * Calls a grant through the harness, as the token endpoint would, and answers as it would. A
	 * `bind` field stands for the binding a sender binding would have read from the request.
	 */
	const grant = async (
		grantType: string,
		as: string,
		form: Record<string, string>,
	): Promise<{ status: number; body: Record<string, string> }> => {
		const binding = form.bind
			? { member: "test", confirmation: form.bind, tokenType: "Test" }
			: undefined;
		const outcome = await app
			.get(grantCalls)
			.call(grantType, as, { grant_type: grantType, ...form }, binding ? { binding } : {})
			.catch((error: unknown) => {
				if (isUnavailable(error)) return undefined;
				throw error;
			});
		if (!outcome) return { status: 503, body: { error: "temporarily_unavailable" } };
		if (outcome.kind === "issued")
			return { status: 200, body: { ...outcome.body } as Record<string, string> };
		const described = outcome.description ? { error_description: outcome.description } : {};
		return { status: 400, body: { error: outcome.error, ...described } };
	};
	/** Redeems a fresh code for `as`; `facts` adds to what the code was issued with. */
	const redeem = async (
		as = "app",
		extra: Record<string, string> = {},
		facts: { readonly acr?: string } = {},
	) => {
		const code = await app.get(codes).issue({
			...facts,
			clientId: as,
			redirectUri: "https://app.example/cb",
			challenge,
			scope: ["read", "write"],
			audience: ["https://api"],
			session: session.id,
			subject: "alice",
		});
		const exchange = async () =>
			(
				await grant("authorization_code", as, {
					code,
					redirect_uri: "https://app.example/cb",
					code_verifier: verifier,
					...extra,
				})
			).body;
		return Object.assign(await exchange(), { again: exchange });
	};
	const refresh = (token: string | undefined, as = "app", extra: Record<string, string> = {}) =>
		grant("refresh_token", as, { refresh_token: token ?? "", ...extra });
	const active = async (token: string | undefined) =>
		(await app.get(tokens).verifyAccess(token ?? "")).kind === "valid";
	return {
		app,
		stores,
		down,
		session,
		post,
		grant,
		redeem,
		refresh,
		active,
		audited: audited.events,
	};
}

/** A rule narrowing to the `resource` asked when the issuance may have it, as resource indicators do. */
const narrowing = defineModule({ name: "narrowing", takes: [] }, (m) => [
	m.contribute(targetRules).by(() => ({
		target: ({ param, audience, within }) => {
			const asked = param("resource");
			if (!asked) return { kind: "audience", audience };
			return within(asked)
				? { kind: "audience", audience: [asked] }
				: { kind: "error", error: "invalid_target", description: `not ${asked}` };
		},
		// A grant that takes no audience gets no resource.
		untargeted: ({ param }) =>
			param("resource")
				? { kind: "error", error: "invalid_target", description: "takes no resource" }
				: undefined,
	})),
]);

describe("refresh tokens", () => {
	it("are issued with a code only to a client allowed the refresh grant", async () => {
		const s = await serve();
		expect(typeof (await s.redeem()).refresh_token).toBe("string");
		expect(await s.redeem("coded")).not.toHaveProperty("refresh_token");
	});

	it("rotate on every use, and a spent one that comes again revokes the family and what it issued", async () => {
		const s = await serve();
		const first = await s.redeem();
		const second = await s.refresh(first.refresh_token);
		expect(second.status).toBe(200);
		expect(second.body.refresh_token).not.toBe(first.refresh_token);
		expect(await s.active(second.body.access_token)).toBe(true);
		expect((await s.refresh(first.refresh_token)).body.error).toBe("invalid_grant");
		expect((await s.refresh(second.body.refresh_token)).body.error).toBe("invalid_grant");
		expect(await s.active(first.access_token)).toBe(false);
		expect(await s.active(second.body.access_token)).toBe(false);
	});

	it("issue access tokens recorded to the family's session, as the code's is", async () => {
		const s = await serve();
		const first = await s.redeem();
		const second = await s.refresh(first.refresh_token);
		for (const token of [first.access_token, second.body.access_token]) {
			const checked = await s.app.get(tokens).verifyAccess(token ?? "");
			if (checked.kind !== "valid") throw new Error("not valid");
			expect(await s.app.get(sessionTokens).sessionOf(checked.id)).toEqual({
				kind: "bound",
				handle: s.session.id,
			});
		}
	});

	// One outside the family but within the client is refused in conformance-code's resource scenes.
	it("refuse an audience neither the family nor the client holds, keeping the token usable, and take the family's own", async () => {
		const s = await serve({ extra: [narrowing] });
		const { refresh_token: token } = await s.redeem();
		expect((await s.refresh(token, "app", { resource: "https://two" })).body).toEqual({
			error: "invalid_target",
			error_description: "not https://two",
		});
		const narrowed = await s.refresh(token, "app", { resource: "https://api" });
		expect(narrowed.status).toBe(200);
		const checked = await s.app.get(tokens).verifyAccess(narrowed.body.access_token ?? "");
		expect(checked.kind === "valid" && checked.grant.audience).toEqual(["https://api"]);
	});

	it("take a resource as a grant that asks it, where the rule refuses one to a grant that takes none", async () => {
		const s = await serve({ extra: [narrowing] });
		const { refresh_token: token } = await s.redeem();
		expect((await s.refresh(token, "app", { resource: "https://api" })).status).toBe(200);
	});

	it("read no resource where no rule is composed", async () => {
		const s = await serve();
		const { refresh_token: token } = await s.redeem();
		expect((await s.refresh(token, "app", { resource: "https://two" })).status).toBe(200);
	});

	it("let at most one of two concurrent uses through, and then neither line goes on", async () => {
		const s = await serve();
		const { refresh_token: token = "" } = await s.redeem();
		const answers = await Promise.all([s.refresh(token), s.refresh(token)]);
		const won = answers.filter((a) => a.status === 200);
		expect(won.length).toBeLessThanOrEqual(1);
		for (const a of won) {
			expect((await s.refresh(a.body.refresh_token)).body.error).toBe("invalid_grant");
			expect(await s.active(a.body.access_token)).toBe(false);
		}
	});

	const direct = (
		s: Awaited<ReturnType<typeof serve>>,
		token: string,
		{
			during = () => {},
			client = {},
			extra = {},
		}: {
			during?: () => Promise<void> | void;
			client?: Partial<Client>;
			extra?: Record<string, string>;
		} = {},
	) => {
		const grant = s.app.get(grantsSeen.seen).find((g) => g.grantType === "refresh_token");
		if (!grant) throw new Error("no refresh_token grant");
		const caller: Client = {
			id: "app",
			kind: "confidential",
			method: "client_secret_post",
			registered: true,
			section: <T>() =>
				({ grants: [], scopes: ["read", "write"], audiences: ["https://api"] }) as T,
			...client,
		};
		const issuing = s.app.get(tokens);
		const input = grantInput(issuing, grant, caller, { refresh_token: token, ...extra });
		return grant
			.handle({
				...input,
				issue: async (g, limits) => {
					await during();
					return input.issue(g, limits);
				},
			})
			.catch((error: unknown) => ({ kind: "thrown" as const, error }));
	};

	it("leaves the presented token usable when a write fails during a refresh", async () => {
		const s = await serve();
		const { refresh_token: token = "" } = await s.redeem();
		const answer = await direct(s, token, {
			during: () => s.stores.down.families.failNext("update"),
		});
		expect(answer?.kind).toBe("thrown");
		expect((await s.refresh(token)).status).toBe(200);
	});

	it("never issues an access token past the family's end", async () => {
		const s = await serve({ lifetime: 60 });
		const { refresh_token: token = "" } = await s.redeem();
		const answer = await s.refresh(token);
		expect(Number(answer.body.expires_in)).toBeLessThanOrEqual(60);
		// Its id is kept past it by an allowance, so a host whose clock lags still revokes it.
		const id = familyNameOf(token);
		const kept = (await s.stores.byFamily.members(id)).map((m) => m.remainingMs);
		expect(Math.min(...kept)).toBeGreaterThan(Number(answer.body.expires_in) * 1000 + 110_000);
	});

	it("never issues an access token past the family's session, when the session ends first", async () => {
		const s = await serve();
		const entry = await s.app.get(sessions).entryOf(s.session.id);
		if (entry.kind !== "entered") throw new Error("not entered");
		// A minute before the session ends, the family (an hour from now) outlives it.
		shift = entry.endsAt - Date.now() - 60_000;
		const { refresh_token: token = "" } = await s.redeem();
		const answer = await s.refresh(token);
		expect(answer.status).toBe(200);
		expect(Number(answer.body.expires_in)).toBeLessThanOrEqual(60);
	});

	it("asks the client's present allowance on every refresh", async () => {
		const s = await serve();
		const { refresh_token: token = "" } = await s.redeem();
		const narrowed = <T>() => ({ grants: [], scopes: ["read"], audiences: ["https://api"] }) as T;
		expect(await direct(s, token, { client: { section: narrowed } })).toMatchObject({
			kind: "error",
			error: "invalid_grant",
		});
		const moved = <T>() =>
			({ grants: [], scopes: ["read", "write"], audiences: ["https://x"] }) as T;
		expect(await direct(s, token, { client: { section: moved } })).toMatchObject({
			kind: "error",
			error: "invalid_grant",
		});
		const read = await direct(s, token, {
			client: { section: narrowed },
			extra: { scope: "read" },
		});
		expect(read?.kind).toBe("issued");
	});

	it("record the family a reuse revokes, with its subject and client, and never a token", async () => {
		const s = await serve();
		const first = await s.redeem();
		const second = await s.refresh(first.refresh_token);
		expect(s.audited.filter((e) => e.kind === "refresh.family_revoked")).toEqual([]);
		await s.refresh(first.refresh_token);
		const revoked = s.audited.filter((e) => e.kind === "refresh.family_revoked");
		expect(revoked.map(({ subject, attributes }) => ({ subject, attributes }))).toEqual([
			{ subject: "alice", attributes: { client: "app" } },
		]);
		for (const token of [first.refresh_token, second.body.refresh_token, first.access_token]) {
			const [, secret = ""] = String(token).split(".");
			expect(JSON.stringify(revoked)).not.toContain(secret);
		}
		// A family a reuse already ended takes no more uses, and records nothing more.
		await s.refresh(second.body.refresh_token);
		expect(s.audited.filter((e) => e.kind === "refresh.family_revoked")).toHaveLength(1);
	});

	it("treat the loser of a race to rotate the same token as a reuse", async () => {
		const s = await serve();
		const { refresh_token: token = "" } = await s.redeem();
		const answers = await Promise.all([direct(s, token), direct(s, token)]);
		expect(answers.filter((a) => a?.kind === "issued").length).toBeLessThanOrEqual(1);
		expect(s.audited.filter((e) => e.kind === "refresh.family_revoked")).toHaveLength(1);
		for (const a of answers) {
			if (a?.kind !== "issued") continue;
			expect((await s.refresh(String(a.body.refresh_token))).body.error).toBe("invalid_grant");
			expect((await s.app.get(tokens).verifyAccess(String(a.body.access_token))).kind).toBe(
				"invalid",
			);
		}
	});

	it("narrow scope for one access token, never widen it, and keep the original grant for the family [rfc6749-6-a] [rfc6749-6-e]", async () => {
		const s = await serve();
		const { refresh_token: token = "" } = await s.redeem();
		const narrowed = await s.refresh(token, "app", { scope: "read" });
		expect(narrowed.body.scope).toBe("read");
		const widened = await s.refresh(narrowed.body.refresh_token, "app", {
			scope: "read admin",
		});
		expect(widened.body.error).toBe("invalid_scope");
		const back = await s.refresh(narrowed.body.refresh_token);
		expect(back.body.scope).toBe("read write");
	});

	it("keep the original grant for an empty scope, as for none, and refuse a malformed one", async () => {
		const s = await serve();
		const { refresh_token: token = "" } = await s.redeem();
		const malformed = await s.refresh(token, "app", { scope: "read  write" });
		expect(malformed.body.error).toBe("invalid_scope");
		const empty = await s.refresh(token, "app", { scope: "" });
		expect([empty.status, empty.body.scope]).toEqual([200, "read write"]);
	});

	it("refuse another client without spending the token [rfc6749-6-c] [rfc6749-10.4-b] [rfc6749-10.4-c]", async () => {
		const s = await serve();
		const { refresh_token: token = "" } = await s.redeem();
		expect((await s.refresh(token, "other")).body.error).toBe("invalid_grant");
		expect((await s.refresh(token)).status).toBe(200);
	});

	it("never outlive the family's lifetime, however often they rotate", async () => {
		const s = await serve({ lifetime: 60 });
		let { refresh_token: token = "" } = await s.redeem();
		shift += 40_000;
		token = (await s.refresh(token)).body.refresh_token ?? "";
		shift += 21_000;
		expect((await s.refresh(token)).body.error).toBe("invalid_grant");
	});

	it("stop working when the session closes", async () => {
		const s = await serve();
		const first = await s.redeem();
		const refreshed = await s.refresh(first.refresh_token);
		await s.app.get(sessions).close(s.session.id);
		expect((await s.refresh(refreshed.body.refresh_token)).body.error).toBe("invalid_grant");
		expect(await s.active(refreshed.body.access_token)).toBe(false);
	});

	it("stop working while the session falls short of a requirement to be used, as a closed one does", async () => {
		const short = { now: false };
		const requirement = defineModule({ name: "short-to-use", takes: [] }, (m) => [
			m.contribute(entryRequirements).by(() => ({
				name: "mfa",
				judges: ["use"],
				admits: async () =>
					short.now ? { kind: "short", answer: { error: "mfa_required" } } : { kind: "admit" },
			})),
		]);
		const s = await serve({ extra: [requirement] });
		const first = await s.redeem();
		short.now = true;
		expect((await s.refresh(first.refresh_token)).body.error).toBe("invalid_grant");
	});

	it("stop working once the session has ended, before the family does", async () => {
		const s = await serve({ lifetime: 7200 });
		const first = await s.redeem();
		// Past the session's lifetime of an hour, within the family's two.
		shift = 3_600_000 + 1_000;
		expect((await s.refresh(first.refresh_token)).body.error).toBe("invalid_grant");
	});

	it("refuse a token with anything after it, without spending the token [rfc6749-6-d]", async () => {
		const s = await serve();
		const first = await s.redeem();
		expect((await s.refresh(`${first.refresh_token}x`)).body.error).toBe("invalid_grant");
		expect((await s.refresh(first.refresh_token)).status).toBe(200);
	});

	it("answer a scope named twice once", async () => {
		const s = await serve();
		const first = await s.redeem();
		const narrowed = await s.refresh(first.refresh_token, "app", { scope: "read read" });
		expect(narrowed.body.scope).toBe("read");
	});

	it("stop working when the subject's authentication is revoked", async () => {
		const s = await serve();
		const { refresh_token: token = "" } = await s.redeem();
		// The revocation boundary must come after the authentication time.
		await new Promise((resolve) => setTimeout(resolve, 5));
		await s.app.get(subjectRevocation).revoke("alice");
		expect((await s.refresh(token)).body.error).toBe("invalid_grant");
	});

	it("issue nothing a contributed policy refuses, and leave the token usable once it allows again", async () => {
		const denying = { on: false };
		const policy = defineModule({ name: "deny-alice", takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "deny-alice",
				judge: async (request) =>
					denying.on && request.grant.subject === "alice"
						? { kind: "refused" as const, reason: "denied", description: "not now" }
						: { kind: "allowed" as const },
			})),
		]);
		const s = await serve({ extra: [policy] });
		const first = await s.redeem();
		denying.on = true;
		const refused = await s.refresh(first.refresh_token);
		expect(refused.status).toBe(400);
		expect(refused.body.access_token).toBeUndefined();
		denying.on = false;
		expect((await s.refresh(first.refresh_token)).status).toBe(200);
	});

	it("tell the policies a refresh continues a grant they already let through", async () => {
		const seen: { grantType: string; continuing?: true }[] = [];
		const watching = defineModule({ name: "watching", takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "watching",
				judge: async (request) => {
					seen.push({
						grantType: request.grantType,
						...(request.continuing ? { continuing: request.continuing } : {}),
					});
					return { kind: "allowed" as const };
				},
			})),
		]);
		const s = await serve({ extra: [watching] });
		const first = await s.redeem();
		expect((await s.refresh(first.refresh_token)).status).toBe(200);
		expect(seen.filter((r) => r.grantType === "refresh_token")).toEqual([
			{ grantType: "refresh_token", continuing: true },
		]);
		expect(seen.filter((r) => r.grantType !== "refresh_token").every((r) => !r.continuing)).toBe(
			true,
		);
	});

	it("are revoked with their family by the issuing client only [rfc7009-2-a] [rfc7009-2.1-c]", async () => {
		const s = await serve();
		const first = await s.redeem();
		const token = first.refresh_token ?? "";
		expect((await s.post("/oauth/revoke", "other", { token })).status).toBe(200);
		expect((await s.refresh(token)).status).toBe(200);
		const next = await s.redeem();
		const hinted = { token: next.refresh_token ?? "", token_type_hint: "refresh_token" };
		expect((await s.post("/oauth/revoke", "app", hinted)).status).toBe(200);
		expect((await s.refresh(next.refresh_token)).body.error).toBe("invalid_grant");
		expect(await s.active(next.access_token)).toBe(false);
	});

	it("answer 503 when the store cannot be reached, never invalid_grant", async () => {
		const s = await serve();
		const { refresh_token: token = "" } = await s.redeem();
		s.stores.down.families.failNext("read");
		const answer = await s.refresh(token);
		expect([answer.status, answer.body.error]).toEqual([503, "temporarily_unavailable"]);
		expect((await s.refresh(token)).status).toBe(200);
	});

	it("never bind a family after it started, so a stolen token cannot lock its holder out", async () => {
		const s = await serve();
		const { refresh_token: first = "" } = await s.redeem("pub");
		const stolen = await s.refresh(first, "pub", { bind: "attacker" });
		expect(stolen.status).toBe(200);
		expect((await s.refresh(first, "pub")).body.error).toBe("invalid_grant");
		expect(
			(await s.refresh(stolen.body.refresh_token, "pub", { bind: "attacker" })).body.error,
		).toBe("invalid_grant");
	});

	it("take a spent token as a reuse before looking at its binding [rfc9700-2.2.2-a]", async () => {
		const s = await serve();
		const { refresh_token: first = "" } = await s.redeem("pub", { bind: "k1" });
		const next = await s.refresh(first, "pub", { bind: "k1" });
		expect((await s.refresh(first, "pub", { bind: "other" })).body.error).toBe("invalid_grant");
		expect((await s.refresh(next.body.refresh_token, "pub", { bind: "k1" })).body.error).toBe(
			"invalid_grant",
		);
	});

	it("bind a public client's family to its binding and ask the same binding after", async () => {
		const s = await serve();
		const { refresh_token: token = "" } = await s.redeem("pub", { bind: "k1" });
		expect((await s.refresh(token, "pub")).body.error).toBe("invalid_grant");
		expect((await s.refresh(token, "pub", { bind: "k2" })).body.error).toBe("invalid_grant");
		const next = await s.refresh(token, "pub", { bind: "k1" });
		expect(next.status).toBe(200);
		const unbound = await s.redeem("pub");
		const later = await s.refresh(unbound.refresh_token, "pub", { bind: "k3" });
		expect((await s.refresh(later.body.refresh_token, "pub")).status).toBe(200);
		const confidential = await s.redeem("app", { bind: "k4" });
		expect((await s.refresh(confidential.refresh_token)).status).toBe(200);
	});

	it("revoke what an expired family issued when its refresh token is revoked [rfc7009-2.1-c]", async () => {
		const s = await serve({ lifetime: 2 });
		const first = await s.redeem();
		shift += 200_000;
		expect((await s.refresh(first.refresh_token)).body.error).toBe("invalid_grant");
		const revoked = await s.post("/oauth/revoke", "app", { token: first.refresh_token ?? "" });
		expect(revoked.status).toBe(200);
		expect(await s.active(first.access_token)).toBe(false);
	});

	it("revoke the families a full session list would drop, and fail rather than lose them", async () => {
		const s = await serve();
		const { refresh_token: kept = "" } = await s.redeem();
		for (let i = 0; i < 999; i++) {
			await s.stores.bySession.add(s.session.id, `filler-${i}`, 86_400_000);
		}
		expect(await s.redeem()).not.toHaveProperty("refresh_token");
		expect((await s.refresh(kept)).body.error).toBe("invalid_grant");
	});

	/** Serves with the refresh addition at hand, and the redemptions codes started. */
	const takingBack = async () => {
		const redemptions: string[] = [];
		const spy = defineModule({ name: "spy", takes: [] }, (m) => [
			m.contribute(additions).by(() => ({
				field: "spy",
				issue: async (redeemed) => {
					redemptions.push(redeemed.redemption);
					return undefined;
				},
			})),
		]);
		const added = collecting("added", additions);
		const s = await serve({ extra: [spy, added.module] });
		const addition = s.app.get(added.seen).find((a) => a.field === "refresh_token");
		const { token: _, ...issued } = await issuedAccess(s.app.get(tokens), {
			subject: "alice",
			issuedTo: "app",
			audience: ["https://api"],
			scope: ["read"],
		});
		const start = (redemption: string, unknown?: true) =>
			addition?.issue({
				...(unknown ? { authenticatedAtUnknown: unknown } : {}),
				redemption,
				client: {
					id: "app",
					kind: "confidential",
					method: "client_secret_post",
					registered: true,
					section: <T>() => ({ grants: ["refresh_token"] }) as T,
				},
				subject: "alice",
				scope: ["read"],
				audience: ["https://api"],
				session: s.session.id,
				authenticatedAt: Date.now(),
				amr: ["pwd"],
				access: issued,
			});
		return { s, redemptions, addition, start };
	};

	it("takes back a family its redemption started", async () => {
		const { s, redemptions, addition } = await takingBack();
		const first = await s.redeem();
		await addition?.revoke?.(redemptions[0] ?? "");
		expect((await s.refresh(first.refresh_token)).body.error).toBe("invalid_grant");
		expect(await s.active(first.access_token)).toBe(false);
	});

	it("give no access token an authentication time the redemption did not know, however often they rotate", async () => {
		const { s, start } = await takingBack();
		const first = await s.refresh(await start("unknown-time", true));
		const second = await s.refresh(first.body.refresh_token);
		for (const rotated of [first, second]) {
			const check = await s.app.get(tokens).verifyAccess(rotated.body.access_token ?? "");
			expect(check.kind === "valid" && "authenticatedAt" in check.grant).toBe(false);
		}
	});

	it("marks a redemption taken back before any family, so none starts", async () => {
		const { addition, start } = await takingBack();
		await addition?.revoke?.("taken-first");
		await addition?.revoke?.("taken-first");
		await expect(start("taken-first")).rejects.toThrow();
	});

	it("refuses to start a family under a name already marked revoked", async () => {
		const { s, start } = await takingBack();
		forced = new Uint8Array(16).fill(7);
		const marked = Buffer.from(forced).toString("base64url");
		await s.stores.kept.records.create(marked, { format: 1, revoked: true } as never, 60_000);
		await expect(start("fresh")).rejects.toThrow();
	});

	it("leaves a revocation pending when a family is placed between finding none and marking it", async () => {
		const { s, addition } = await takingBack();
		const family = "f".repeat(22);
		await s.stores.marks.records.create("raced", toStoredRedemption({ format: 1, family }), 60_000);
		s.stores.landing(async (id) => {
			await s.stores.kept.records.create(id, toStored({ format: 1, revoked: true }), 60_000);
		});
		await expect(addition?.revoke?.("raced")).rejects.toSatisfy(isUnavailable);
	});

	it("refuses to take back a redemption whose record it cannot read", async () => {
		const { s, addition } = await takingBack();
		await s.stores.marks.records.create("odd", { format: 2 } as never, 60_000);
		await expect(addition?.revoke?.("odd")).rejects.toThrow();
	});

	it("end with the code they came with, when that code comes again", async () => {
		const s = await serve();
		const first = await s.redeem();
		const next = await s.refresh(first.refresh_token);
		await first.again();
		expect((await s.refresh(next.body.refresh_token)).body.error).toBe("invalid_grant");
		expect(await s.active(next.body.access_token)).toBe(false);
	});

	it("revoke an access token its family's full list would drop, and fail rather than lose it", async () => {
		// A family and a session that outlive its tokens, so each token ends a second after the one before.
		const s = await serve({
			lifetime: 86_400,
			accessLifetime: 600,
			caps: { sessionFamilies: 1000, issuedAccess: 2 },
		});
		const first = await s.redeem();
		shift += 1000;
		const second = await s.refresh(first.refresh_token);
		shift += 1000;
		expect((await s.refresh(second.body.refresh_token)).status).toBe(503);
		expect(await s.active(first.access_token)).toBe(false);
		expect(await s.active(second.body.access_token)).toBe(true);
	});

	it("tell a refresh token it does not know from one it revoked, and written only when it revokes", async () => {
		const kinds = collecting("kinds", revocableKinds);
		const s = await serve({ extra: [kinds.module] });
		const kind = s.app.get(kinds.seen).find((k) => k.hint === "refresh_token");
		const client = { id: "app" } as Client;
		const first = await s.redeem();
		expect(await kind?.revoke(`${"z".repeat(22)}.${"z".repeat(43)}`, client)).toBe("unknown");
		expect(await kind?.revoke(first.refresh_token ?? "", { id: "other" } as Client)).toBe("done");
		expect(await kind?.revoke(first.refresh_token ?? "", client)).toBe("written");
		expect(await kind?.revoke(first.refresh_token ?? "", client)).toBe("done");
	});

	it("keep a family listed until its tokens are revoked, and finish it in a sweep", async () => {
		const s = await serve();
		const first = await s.redeem();
		const id = familyNameOf(first.refresh_token);
		const next = await s.refresh(first.refresh_token);
		s.down.tokens.unavailable("revokeAccess", "revokeReferenced");
		expect((await s.refresh(first.refresh_token)).status).toBe(503);
		expect(s.stores.kept.pending()).toEqual([id]);
		expect((await s.refresh(next.body.refresh_token)).body.error).toBe("invalid_grant");
		s.down.tokens.restore();
		await new Promise((resolve) => setTimeout(resolve, 1300));
		expect(s.stores.kept.pending()).toEqual([]);
		expect(await s.active(next.body.access_token)).toBe(false);
	});

	it("fail their access tokens as soon as the family ends, before the sweep revokes them", async () => {
		const s = await serve();
		const first = await s.redeem();
		const next = await s.refresh(first.refresh_token);
		s.down.tokens.unavailable("revokeAccess", "revokeReferenced");
		// A reuse ends the family; its access tokens wait on the list to be revoked.
		expect((await s.refresh(first.refresh_token)).status).toBe(503);
		expect(await s.active(next.body.access_token)).toBe(false);
		s.down.tokens.restore();
	});

	it("mark a family revoked when its session closes before its record is written", async () => {
		const s = await serve();
		const starting = "y".repeat(22);
		await s.stores.bySession.add(s.session.id, starting, 60_000);
		await s.app.get(sessions).close(s.session.id);
		expect(s.stores.kept.peek(starting)).toEqual({ format: 1, revoked: true });
		expect(s.stores.kept.pending()).toEqual([]);
	});

	it("finish revoking a family left pending", async () => {
		const s = await serve();
		const first = await s.redeem();
		await s.stores.kept.deferred.add(familyNameOf(first.refresh_token));
		await new Promise((resolve) => setTimeout(resolve, 1300));
		expect((await s.refresh(first.refresh_token)).body.error).toBe("invalid_grant");
		expect(await s.active(first.access_token)).toBe(false);
	});

	it("refuse to start without revocable access tokens", async () => {
		await expect(serve({ revocation: "unsupported" })).rejects.toMatchObject({
			refusals: expect.arrayContaining([expect.objectContaining({ where: "refresh" })]),
		});
	});
});

describe("lineage", () => {
	type Served = Awaited<ReturnType<typeof serve>>;
	const idOf = async (s: Served, token: string) => {
		const check = await s.app.get(tokens).verifyAccess(token);
		return check.kind === "valid" ? check.id : "";
	};
	const issue = (s: Served, notAfter?: number) =>
		issuedAccess(
			s.app.get(tokens),
			{ subject: "alice", issuedTo: "app", audience: ["https://api"], scope: ["read"] },
			notAfter === undefined ? {} : { notAfter },
		);
	/** What the `family` tie answers for a token. */
	const tieOf = (s: Served, tokenId: string) => {
		const family = s.app.get(tiesSeen.seen).find((t) => t.name === "family");
		if (!family) throw new Error("no family tie");
		return family.tieOf(tokenId);
	};
	/** The family of a code's first access token, as the tie holds it. */
	const familyOf = async (s: Served, first: Record<string, string>) => {
		const found = await tieOf(s, await idOf(s, first.access_token ?? ""));
		if (found.kind !== "held") throw new Error(`no family: ${found.kind}`);
		return found;
	};
	const ended = { kind: "ended", reason: "family has ended" };
	const beginning = async (s: Served, as: string) => {
		const client = (await s.app.get(clients).find(as)) as Client;
		const { token: _, ...access } = await issue(s);
		const base = { client, subject: "alice", scope: ["read"], audience: ["https://api"] };
		return { ...base, authenticatedAt: Date.now(), amr: ["hwk"], access };
	};

	it("answers the family of each access token a family issued, and none for another", async () => {
		const s = await serve({ lifetime: 60 });
		const first = await s.redeem();
		const found = await familyOf(s, first);
		expect(found.ends).toBeLessThanOrEqual(Date.now() + 60_000);
		const next = await s.refresh(first.refresh_token);
		const rotated = await tieOf(s, await idOf(s, next.body.access_token ?? ""));
		expect(rotated).toMatchObject({ kind: "held", ends: found.ends });
		const coded = await s.redeem("coded");
		const none = { kind: "none" };
		expect(await tieOf(s, await idOf(s, coded.access_token ?? ""))).toEqual(none);
		expect(await tieOf(s, (await issue(s)).id)).toEqual(none);
	});

	it("never hands out a family's own name", async () => {
		const s = await serve();
		const first = await s.redeem();
		const name = familyNameOf(first.refresh_token);
		expect(JSON.stringify(await familyOf(s, first))).not.toContain(name);
	});

	it("answers ended once the family is revoked, its session closes, it runs out or is lost", async () => {
		const reused = await serve();
		const first = await reused.redeem();
		const id = await idOf(reused, first.access_token ?? "");
		await reused.refresh(first.refresh_token);
		await reused.refresh(first.refresh_token);
		expect(await tieOf(reused, id)).toEqual(ended);
		await stop();
		const closed = await serve();
		const opened = await closed.redeem();
		const openedId = await idOf(closed, opened.access_token ?? "");
		await closed.app.get(sessions).close(closed.session.id);
		expect(await tieOf(closed, openedId)).toEqual(ended);
		await stop();
		const s = await serve({ lifetime: 2 });
		const short = await s.redeem();
		const shortId = await idOf(s, short.access_token ?? "");
		shift += 2000;
		expect(await tieOf(s, shortId)).toEqual(ended);
		await s.stores.links.records.create("lost", { format: 1, family: "gone" } as never, 60_000);
		expect(await tieOf(s, "lost")).toEqual(ended);
		await s.stores.links.records.create("odd", { format: 2 } as never, 60_000);
		expect(isUnavailable(await tieOf(s, "odd").catch((e) => e))).toBe(true);
	});

	it("adopts a token into a live family, so the family's end revokes it too", async () => {
		const s = await serve();
		const first = await s.redeem();
		const found = await familyOf(s, first);
		const issued = await issue(s, found.ends);
		expect(await found.join(issued)).toBe(true);
		expect(await tieOf(s, issued.id)).toMatchObject({ kind: "held" });
		await s.refresh(first.refresh_token);
		await s.refresh(first.refresh_token);
		expect(await s.active(issued.token)).toBe(false);
	});

	it("adopts the same token again, and never a token id another family holds", async () => {
		const s = await serve();
		const found = await familyOf(s, await s.redeem());
		const issued = await issue(s, found.ends);
		expect(await found.join(issued)).toBe(true);
		expect(await found.join(issued)).toBe(true);
		const taken = await issue(s, found.ends);
		await s.stores.links.records.create(taken.id, { format: 1, family: "other" } as never, 60_000);
		expect(isUnavailable(await found.join(taken).catch((e) => e))).toBe(true);
	});

	it("ties a token to its family as `family`: none, ended, or held to the family's end, joining one issued from it", async () => {
		const s = await serve();
		const first = await s.redeem();
		const held = await familyOf(s, first);
		expect(held.session).toBeUndefined();
		expect(await tieOf(s, (await issue(s)).id)).toEqual({ kind: "none" });
		const joined = await issue(s, held.ends);
		expect(await held.join(joined)).toBe(true);
		expect((await tieOf(s, joined.id)).kind).toBe("held");
		await s.post("/oauth/revoke", "app", { token: first.refresh_token ?? "" });
		expect(await tieOf(s, joined.id)).toEqual(ended);
		const late = await issue(s, held.ends);
		expect(await held.join(late)).toBe(false);
		expect(await s.active(late.token)).toBe(false);
	});

	it("has a token token-exchange issues from a family's access token end with the family", async () => {
		const s = await serve({ extra: [tokenExchange] });
		const first = await s.redeem("exchanger");
		const exchange = () =>
			s.grant(exchangeType, "exchanger", {
				subject_token: first.access_token ?? "",
				subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
			});
		const exchanged = await exchange();
		expect(exchanged.status).toBe(200);
		expect(await s.active(exchanged.body.access_token)).toBe(true);
		await s.refresh(first.refresh_token, "exchanger");
		await s.refresh(first.refresh_token, "exchanger");
		expect(await s.active(exchanged.body.access_token)).toBe(false);
		// The family's end revoked the subject token too, so it no longer validates.
		expect((await exchange()).body).toMatchObject({ error: "invalid_request" });
	});

	it("revokes the token and answers ended for a family that has ended", async () => {
		const s = await serve();
		const first = await s.redeem();
		const found = await familyOf(s, first);
		await s.post("/oauth/revoke", "app", { token: first.refresh_token ?? "" });
		const issued = await issue(s, found.ends);
		expect(await found.join(issued)).toBe(false);
		expect(await s.active(issued.token)).toBe(false);
	});

	it("revokes the token when the family ends while it is adopted", async () => {
		const s = await serve();
		const first = await s.redeem();
		const found = await familyOf(s, first);
		const issued = await issue(s, found.ends);
		// The family's tokens are listed and revoked just before this one joins the list.
		const add = s.stores.byFamily.add.bind(s.stores.byFamily);
		s.stores.byFamily.add = async (...args) => {
			await s.post("/oauth/revoke", "app", { token: first.refresh_token ?? "" });
			return add(...args);
		};
		expect(await found.join(issued)).toBe(false);
		expect(await s.active(issued.token)).toBe(false);
	});

	it("revokes and refuses a token that would outlive the family", async () => {
		const s = await serve({ lifetime: 60 });
		const found = await familyOf(s, await s.redeem());
		const issued = await issue(s);
		await expect(found.join(issued)).rejects.toThrow();
		expect(await s.active(issued.token)).toBe(false);
	});

	it("revokes what a full family list pushes out to adopt a token, and fails", async () => {
		const s = await serve({ lifetime: 86_400, caps: { sessionFamilies: 1000, issuedAccess: 1 } });
		const first = await s.redeem();
		const found = await familyOf(s, first);
		shift += 1000;
		const issued = await issue(s, found.ends);
		expect(isUnavailable(await found.join(issued).catch((e) => e))).toBe(true);
		expect(await s.active(first.access_token)).toBe(false);
	});

	it("starts a family bound to no session, which still ends with its subject's revocation", async () => {
		const s = await serve();
		const begun = await beginning(s, "app");
		const token = await s.app.get(lineage).start(begun);
		expect(await tieOf(s, begun.access.id)).toMatchObject({ kind: "held" });
		await s.app.get(sessions).close(s.session.id);
		const next = await s.refresh(token);
		expect(next.status).toBe(200);
		await new Promise((resolve) => setTimeout(resolve, 5));
		await s.app.get(subjectRevocation).revoke("alice");
		expect((await s.refresh(next.body.refresh_token)).body.error).toBe("invalid_grant");
	});

	it("refuses a family's token at exactly the family's end, and takes it two seconds before", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const s = await serve();
		// A family bound to no session, so only the family's own end can refuse it.
		const token = await s.app.get(lineage).start(await beginning(s, "app"));
		const stored = await s.stores.kept.records.read(familyNameOf(token));
		const end = (stored as unknown as { expiresAt: number }).expiresAt;
		// Two seconds before: the access token, cut to the family's end in whole seconds, still has over one.
		shift = end - Date.now() - 2000;
		const before = await s.refresh(token);
		expect([before.status, before.body.expires_in]).toEqual([200, 2]);
		shift += 2000;
		expect((await s.refresh(before.body.refresh_token)).body.error).toBe("invalid_grant");
	});

	it("carries the acr a code met to every access token its family issues", async () => {
		const s = await serve();
		const first = await s.redeem("app", {}, { acr: "urn:example:strong" });
		const refreshed = await s.refresh(first.refresh_token);
		const check = await s.app.get(tokens).verifyAccess(String(refreshed.body.access_token));
		expect(check.kind === "valid" && check.grant.acr).toBe("urn:example:strong");
	});

	it("gives every rotated access token the family's amr, authentication time and acr", async () => {
		const s = await serve();
		const begun = { ...(await beginning(s, "app")), acr: "urn:example:strong" };
		const first = await s.refresh(await s.app.get(lineage).start(begun));
		const second = await s.refresh(first.body.refresh_token);
		for (const rotated of [first, second]) {
			const check = await s.app.get(tokens).verifyAccess(rotated.body.access_token ?? "");
			expect(check.kind === "valid" && check.grant).toMatchObject({
				amr: ["hwk"],
				// A token carries the authentication time to the second (`auth_time`).
				authenticatedAt: Math.floor(begun.authenticatedAt / 1000) * 1000,
				acr: "urn:example:strong",
			});
		}
		const plain = await s.refresh(await s.app.get(lineage).start(await beginning(s, "app")));
		const check = await s.app.get(tokens).verifyAccess(plain.body.access_token ?? "");
		expect(check.kind === "valid" && "acr" in check.grant).toBe(false);
	});

	it("gives no rotated access token an authentication time the family's beginning did not know", async () => {
		const s = await serve();
		const begun = { ...(await beginning(s, "app")), authenticatedAtUnknown: true as const };
		const first = await s.refresh(await s.app.get(lineage).start(begun));
		const second = await s.refresh(first.body.refresh_token);
		for (const rotated of [first, second]) {
			const check = await s.app.get(tokens).verifyAccess(rotated.body.access_token ?? "");
			expect(check.kind === "valid" && "authenticatedAt" in check.grant).toBe(false);
		}
	});

	it("reads a family kept in the format before, as one whose authentication time is known", async () => {
		const s = await serve();
		const name = randomBytes(16).toString("base64url");
		const secret = randomBytes(32).toString("base64url");
		const before = {
			format: 1,
			current: createHash("sha256").update(secret).digest("base64url"),
			clientId: "app",
			subject: "alice",
			scope: ["read"],
			audience: ["https://api"],
			authenticatedAt: Date.now(),
			amr: ["hwk"],
			expiresAt: Date.now() + 60_000,
		};
		await s.stores.kept.records.create(name, before as never, 60_000);
		const next = await s.refresh(`${name}.${secret}`);
		const check = await s.app.get(tokens).verifyAccess(next.body.access_token ?? "");
		expect(check.kind === "valid" && check.grant.authenticatedAt).toBeTypeOf("number");
		expect(await s.stores.kept.records.read(name)).toMatchObject({ format: 2 });
	});

	it("binds a confidential client's family too where the section says so", async () => {
		const s = await serve({ bindConfidential: true });
		const binding = { member: "test", confirmation: "k1", tokenType: "Test" };
		const app = await s.app.get(lineage).start({ ...(await beginning(s, "app")), binding });
		expect((await s.refresh(app)).body.error).toBe("invalid_grant");
		expect((await s.refresh(app, "app", { bind: "k1" })).status).toBe(200);
	});

	it("starts a family only for a client allowed to refresh, bound only for a public client", async () => {
		const s = await serve();
		expect(await s.app.get(lineage).start(await beginning(s, "coded"))).toBeUndefined();
		const binding = { member: "test", confirmation: "k1", tokenType: "Test" };
		const pub = await s.app.get(lineage).start({ ...(await beginning(s, "pub")), binding });
		expect((await s.refresh(pub, "pub")).body.error).toBe("invalid_grant");
		expect((await s.refresh(pub, "pub", { bind: "k1" })).status).toBe(200);
		const app = await s.app.get(lineage).start({ ...(await beginning(s, "app")), binding });
		expect((await s.refresh(app)).status).toBe(200);
	});
});

it("reads a family's lifetime with its unit, in whole seconds, a day unless set", () => {
	const lifetimeOf = (settings: object) => section.safeParse(settings).data?.lifetime;
	expect([{}, { lifetime: "2h" }].map(lifetimeOf)).toEqual([86_400, 7200]);
	const refused = [{ "lifetime-seconds": 60 }, { lifetime: 3600 }, { "sweep-interval": 30 }];
	expect(refused.map(lifetimeOf)).toEqual([undefined, undefined, undefined]);
});

it("takes all its module names, its confidential clients' families bound or not", async () => {
	for (const bindConfidential of [false, true]) {
		const { input } = assembly({ bindConfidential });
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(input))["refresh"], String(bindConfidential)).toBeUndefined();
	}
});
