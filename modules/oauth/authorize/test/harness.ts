import { createHash } from "node:crypto";
import acrModule from "@mod/acr/module";
import { acrConfig } from "@mod/acr/testing";
import type { AuditEvent } from "@mod/audit";
import { auditStandIn } from "@mod/audit/testing";
import { claimScopes } from "@mod/claims-selection";
import claimsSelectionModule from "@mod/claims-selection/module";
import { claimsSelectionInMemory } from "@mod/claims-selection/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import codeGrantModule from "@mod/code-grant/module";
import { codeGrantConfig } from "@mod/code-grant/testing";
import codeGrantStore from "@mod/code-grant-store/module";
import type { StoredAsk, StoredGrant } from "@mod/consent";
import consentModule from "@mod/consent/module";
import { consentConfig, consentStoresOn, firstPartyFor } from "@mod/consent/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, isUnavailable, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog, switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import { amrSources } from "@mod/login-gates";
import gatesModule from "@mod/login-gates/module";
import rateLimitModule from "@mod/rate-limit/module";
import { type ReauthStore, reauthStore, type StoredReauth } from "@mod/reauth";
import reauthModule from "@mod/reauth/module";
import { memoryRecords } from "@mod/records/testing";
import { redirectsFor } from "@mod/redirect-uris/testing";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { openedOf, sessionStandIn } from "@mod/session/testing";
import sessionParticipants from "@mod/session-participants/module";
import bridgeModule from "@mod/session-tokens/module";
import { sessionTokensInMemory } from "@mod/session-tokens/testing";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { type Tokens, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { expect } from "vitest";
import declared from "../src/audit-events.ts";
import { hintReaders } from "../src/contract.ts";
import authorizeModule from "../src/module.ts";
import { authorizeConfig } from "../src/testing.ts";

export let now = 1_800_000_000_000;
/** Moves the kernel's clock on by `ms`. */
export const advance = (ms: number) => {
	now += ms;
};
export const logged = recordingLog();
export const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
export const warnings = () =>
	logged.lines().filter((line) => line.event === "authorize.unavailable");
let stop = async () => {};
/** Stops the app `serve` last started; each test file calls it after each test. */
export const stopServed = () => stop();

export const issuer = "https://as.example";
export const callback = "https://app.example/cb";
export const verifier = "v".repeat(43);
export const challenge = createHash("sha256").update(verifier).digest("base64url");
export const client = (
	id: string,
	extra: Record<string, unknown> = {},
	grants = ["authorization_code"],
) =>
	confidentialClient({
		id,
		sections: {
			...allowancesFor({
				grants,
				scopes: ["openid", "read", "write"],
				"default-scopes": ["read"],
				audiences: ["https://api"],
			}),
			...redirectsFor([callback, "http://127.0.0.1:9000/cb"]),
			...extra,
		},
	});

export async function serve(
	options: {
		revocable?: boolean;
		codeGrant?: Record<string, unknown>;
		authorize?: Record<string, unknown>;
		/** The acr table, each acr and the amr sets that meet it. */
		acr?: Record<string, string[][]>;
		extra?: Module[];
		/** The amr the deployment's ways of logging in declare. */
		proves?: string[];
		/** The rate-limit module; its stand-in never fails to count. */
		rateLimit?: Module;
		/** False leaves out the consent page, so consent cannot ask. */
		asking?: boolean;
		/** The deployment's environment, production unless a test tries a page on this machine. */
		environment?: "production" | "development";
		/** The package's claims-parameter; true unless a test is about false. */
		claimsParameter?: boolean;
		/** claims-selection's store; the in-memory one unless a test makes it fail. */
		selectionStore?: Module;
	} = {},
) {
	const proving = defineModule({ name: "proving", replicaSafe: false, takes: [] }, (m) => [
		m
			.contribute(amrSources)
			.by(() => ({ name: "proving", amr: options.proves ?? ["pwd", "otp", "mfa"] })),
	]);
	const simulated = simulatedStore();
	const reauths = memoryRecords<StoredReauth>(() => now, { shards: 1, perShard: 1 });
	const down = {
		reauths: unavailableSwitch<ReauthStore>("reauth store"),
		tokens: unavailableSwitch<Tokens>("tokens"),
	};
	const reauthStand = defineModule({ name: "reauth-store", replicaSafe: false, takes: [] }, (m) => [
		m
			.provide(reauthStore)
			.by(() =>
				down.reauths.wrap({ save: reauths.records.create, update: reauths.records.change }),
			),
	]);
	const consentStores = consentStoresOn({
		grants: memoryRecords<StoredGrant>(() => now, { shards: 1, perShard: 1 }),
		asks: memoryRecords<StoredAsk>(() => now, { shards: 1, perShard: 1 }),
	});
	const audit = auditStandIn();
	recorded = audit.events;
	// The composition as one value, for a test of what its modules take.
	const input = {
		modules: [
			http,
			switchedModule(tokensStandIn({ revocable: options.revocable ?? true }), tokens, down.tokens),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			sessionStandIn,
			sessionParticipants,
			subjectRevocationStandIn,
			consentModule,
			consentStores,
			csrfStandIn,
			cookiesModule,
			simulated.module,
			bridgeModule,
			sessionTokensInMemory().module,
			codeGrantModule,
			codeGrantStore,
			authorizeModule,
			reauthStand,
			reauthModule,
			options.rateLimit ?? rateLimitModule,
			audit.module,
			acrModule,
			gatesModule,
			proving,
			claimsSelectionModule,
			options.selectionStore ?? claimsSelectionInMemory().module,
			scoping,
			hinting,
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig({ environment: options.environment ?? "production" }),
			...httpConfig({ "trusted-proxies": ["127.0.0.1"], "public-origin": issuer }),
			...issuerConfig({ url: issuer }),
			...clientsConfig([
				client("app", firstPartyFor(true)),
				client("wide", {
					...firstPartyFor(true),
					...allowancesFor({
						grants: ["authorization_code"],
						scopes: ["read"],
						"default-scopes": ["read"],
						audiences: ["https://api", "https://two"],
					}),
				}),
				client("third"),
				client("nocode", firstPartyFor(true), ["client_credentials"]),
				confidentialClient({
					id: "nodefault",
					sections: {
						...allowancesFor({ grants: ["authorization_code"], scopes: ["read"] }),
						...redirectsFor([callback]),
						...firstPartyFor(true),
					},
				}),
				confidentialClient({
					id: "openid-default",
					sections: {
						...allowancesFor({
							grants: ["authorization_code"],
							scopes: ["openid", "read"],
							"default-scopes": ["openid"],
						}),
						...redirectsFor([callback]),
						...firstPartyFor(true),
					},
				}),
				confidentialClient({
					id: "empty",
					sections: {
						...allowancesFor({ grants: ["authorization_code"], scopes: [], "default-scopes": [] }),
						...redirectsFor([callback]),
					},
				}),
				publicClient({
					id: "pub",
					sections: {
						...allowancesFor({
							grants: ["authorization_code"],
							scopes: ["read"],
							"default-scopes": ["read"],
						}),
						...redirectsFor(["http://[::1]:7000/cb"]),
						...firstPartyFor(true),
					},
				}),
			]),
			...(options.asking === false ? { consent: {} } : consentConfig()),
			// Most scenes here are not about OpenID Connect, so they leave out openid.
			...authorizeConfig({
				"oidc-mode": "dual",
				"claims-parameter": options.claimsParameter ?? true,
				...options.authorize,
			}),
			...acrConfig(options.acr ?? {}),
			...codeGrantConfig({ "code-lifetime": "1m", ...options.codeGrant }),
		},
		runtime,
	};
	const app = await assemble(input);
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	const opened = app.get(sessions);
	const login = async (
		subject = "alice",
		amr = ["pwd"],
		authenticatedAt: number | "unknown" = runtime.clock.now(),
	) => {
		const facts = { subject, amr, authenticatedAt };
		const { cookies } = openedOf(await opened.open(testRequest(), facts));
		return cookies[0]?.split(";")[0] ?? "";
	};
	const authorize = async (params: Record<string, string> | string, cookie = "") => {
		const query = typeof params === "string" ? params : new URLSearchParams(params).toString();
		const res = await fetch(`${base}/oauth/authorize?${query}`, {
			redirect: "manual",
			headers: { "x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.1", cookie },
		});
		const location = res.headers.get("location") ?? "";
		return {
			status: res.status,
			location,
			at: location ? new URL(location) : undefined,
			text: await res.text(),
		};
	};
	/** Redeems a code through the grant harness, answering as the token endpoint would. */
	const token = async (
		form: Record<string, string>,
		id = "app",
	): Promise<{ status: number; body: Record<string, unknown> }> => {
		const params = { grant_type: "authorization_code", ...form };
		const outcome = await app
			.get(grantCalls)
			.call("authorization_code", id, params)
			.catch((error: unknown) => {
				if (isUnavailable(error)) return undefined;
				throw error;
			});
		if (!outcome) return { status: 503, body: { error: "temporarily_unavailable" } };
		if (outcome.kind === "issued") return { status: 200, body: { ...outcome.body } };
		const described = outcome.description ? { error_description: outcome.description } : {};
		return { status: 400, body: { error: outcome.error, ...described } };
	};
	return {
		app,
		input,
		simulated,
		down,
		login,
		authorize,
		token,
		opened,
		base,
		events: audit.events,
	};
}

/** The claim scopes oidc would contribute, here a stand-in: groups' scope is one no client is allowed. */
export const claimScopeTable = new Map([
	["name", "read"],
	["email", "write"],
	["groups", "admin"],
]);
export const scoping = defineModule({ name: "scoping", replicaSafe: false, takes: [] }, (m) => [
	m.contribute(claimScopes).by(() => ({ scopeOf: (claim: string) => claimScopeTable.get(claim) })),
]);

/**
 * The hint reader oidc would contribute, here a stand-in: `id:<subject>` is an ID token it issued
 * naming that subject, expired or not, and any other none it takes.
 */
export const hinting = defineModule({ name: "hinting", replicaSafe: false, takes: [] }, (m) => [
	m.contribute(hintReaders).by(() => ({
		read: async (hint: string) =>
			hint.startsWith("id:")
				? ({ kind: "subject", subject: hint.slice(3) } as const)
				: ({ kind: "invalid" } as const),
	})),
]);

export const request = (extra: Record<string, string> = {}) => ({
	response_type: "code",
	client_id: "app",
	redirect_uri: callback,
	state: "s1",
	code_challenge: challenge,
	code_challenge_method: "S256",
	...extra,
});

/** The audit events of the latest composition. */
export let recorded: readonly AuditEvent[] = [];
/** Every authorize event a test recorded is one the module declares, with attributes it declares; each test file calls it after each test. */
export const eventsDeclared = () => {
	for (const { kind, attributes } of recorded.filter((e) => e.kind.startsWith("authorize."))) {
		const known: readonly string[] = declared[kind as keyof typeof declared]?.attributes ?? [];
		expect(known, `${kind} is declared`).not.toEqual([]);
		expect(
			Object.keys(attributes ?? {}).filter((name) => !known.includes(name)),
			kind,
		).toEqual([]);
	}
	recorded = [];
};
