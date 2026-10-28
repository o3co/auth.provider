import { auditStandIn } from "@mod/audit/testing";
import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import {
	clientSecret,
	clientsConfig,
	confidentialClient,
	publicClient,
} from "@mod/clients/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { type HttpRequest, type HttpResponse, type Route, routes } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import type { Module } from "@mod/kernel";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import {
	type DelegatedExchange,
	type Delegation,
	type DelegationStart,
	type UpstreamRefresh,
	UpstreamRefused,
	type UpstreamTokens,
	upstreams,
} from "@mod/upstreams";
import { grantIntents, grantsBrowsers } from "../src/contract.ts";
import { browserStandIn } from "../src/intents/test/stand-in.ts";
import federationGrants from "../src/module.ts";
import { type FederationGrantsSettings, federationGrantsConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

export const origin = "https://issuer.example";
export const back = "https://worker.example/connected";
export const scopes = ["openid", "offline_access", "read"];

/** What the test's upstream answers, set by each test. */
export interface Scripted {
	/** The login a code's exchange answers, or how it fails. */
	exchange: (x: DelegatedExchange) => Promise<unknown>;
	refreshes: (UpstreamRefresh | "unreachable" | "refused" | (() => never))[];
	/** Starts throw at once, as a type that cannot build its URL does. */
	startThrows: boolean;
	/** Starts are refused as a value, as a type refuses a start it does not take. */
	startRefused: boolean;
	/** The IdP no longer offers its delegation, as after the operator took it away. */
	withdrawn: boolean;
}

/** Tokens an upstream gives, bearer with a refresh token and five minutes, unless a test says. */
export const upstreamTokens = (more: Partial<Record<keyof UpstreamTokens, unknown>> = {}) =>
	({
		accessToken: "up-1",
		tokenType: "Bearer",
		refreshToken: "up-refresh-1",
		expiresInSeconds: 300,
		scope: scopes,
		...more,
	}) as unknown as UpstreamTokens;

/** The login an upstream answers a code with, for `u-alice` unless said. */
export const upstreamLogin = (tokens: unknown = upstreamTokens(), subject = "u-alice") => ({
	subject,
	amr: [],
	issuer: "https://up.example",
	tokens,
});

const probed = contract<readonly Route[]>("test.routes");

const unanswered = async (): Promise<HttpResponse> => ({ status: 501, headers: {} });
/**
 * The browser half contributed, so the browser routes answer without federation-grants' own: each a
 * plain 501. The harness walks intents with `intents`' `browserStandIn` instead.
 */
const unansweredBrowser = defineModule(
	{ name: "browser-stand-in", replicaSafe: true, takes: [] },
	(m) => [
		m.contribute(grantsBrowsers).by(() => ({
			connect: unanswered,
			question: unanswered,
			decide: unanswered,
			callback: unanswered,
		})),
	],
);

type Answer = {
	status: number;
	headers: Record<string, string>;
	json?: Record<string, unknown> | undefined;
	text?: string;
	cookies: readonly string[];
};
/** An answer in a line: its status, the token handed or the error and its description, any retry-after. */
export const said = (answer: Answer) =>
	[
		answer.status,
		answer.status === 200 ? answer.json?.access_token : answer.json?.error,
		answer.json?.error_description,
		answer.headers["retry-after"],
	]
		.filter((part) => part !== undefined)
		.join(" ");

const read = (response: HttpResponse): Answer => {
	const body = response.body as { json?: Record<string, unknown> } | string | undefined;
	return {
		status: response.status,
		headers: { ...response.headers },
		...(typeof body === "string" ? { text: body } : { json: body?.json }),
		cookies: response.cookies ?? [],
	};
};

/** federation-grants with stand-ins, a test upstream `corp` behind the connection `cal`, and two clients that may use it. */
export async function harness(
	options: {
		readonly settings?: Partial<FederationGrantsSettings>;
		/** The resource the connection `cal` is for. */
		readonly resource?: string;
		/** The public origin; none for `null`. */
		readonly origin?: string | null;
		/** Another composition's stores, as after a restart with other settings. */
		readonly stores?: ReturnType<typeof memoryStores>;
		/** The seal section in place of the test's one key: a ring with past keys, say. */
		readonly seal?: Readonly<Record<string, unknown>>;
		/** Modules composed beside federation-grants. */
		readonly modules?: readonly Module[];
		/** The module contributing the browser half, the stand-in unless said; none for `null`. */
		readonly browserHalf?: Module | null;
	} = {},
) {
	let now = 1_800_000_000_000;
	const logged = recordingLog();
	const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
	const stores = options.stores ?? memoryStores(() => now, 3);
	const recorded = auditStandIn();
	const script: Scripted = {
		exchange: async () => upstreamLogin(),
		refreshes: [],
		startThrows: false,
		startRefused: false,
		withdrawn: false,
	};
	const asked = {
		starts: [] as DelegationStart[],
		refreshes: [] as [string, readonly string[], string | undefined][],
	};
	const delegation: Delegation = {
		authorizationUrl: (start) => {
			if (script.startThrows) throw new Error("cannot build");
			if (script.startRefused) return { kind: "refused" };
			asked.starts.push(start);
			return `https://up.example/authorize?state=${start.state}`;
		},
		exchange: (x) => script.exchange(x) as ReturnType<Delegation["exchange"]>,
		refresh: async (token, scope, resource) => {
			asked.refreshes.push([token, scope, resource]);
			const next = script.refreshes.shift();
			if (next === "unreachable") throw new Unavailable("test upstream");
			if (next === "refused") throw new UpstreamRefused();
			if (typeof next === "function") return next();
			const fresh = upstreamTokens({ accessToken: `up-${asked.refreshes.length + 1}` });
			return next ?? ({ kind: "refreshed", tokens: fresh } as UpstreamRefresh);
		},
	};
	const stubs = defineModule({ name: "stubs", replicaSafe: false, takes: [routes] }, (m) => [
		m.provide(upstreams).by(() => ({
			of: (idp) => (idp === "corp" && !script.withdrawn ? { delegation } : undefined),
		})),
		m.provide(probed).by((c) => c.collect(routes)),
	]);
	const worker = (id: string) =>
		confidentialClient({
			id,
			method: "client_secret_basic",
			sections: { "federation-grants": { connections: ["cal"], "return-uris": [back] } },
		});
	const app = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			sessionStandIn,
			csrfStandIn,
			cookiesModule,
			subjectRevocationStandIn,
			rateLimitStandIn,
			recorded.module,
			sealModule,
			stores.module,
			stubs,
			federationGrants,
			...(options.browserHalf === null ? [] : [options.browserHalf ?? unansweredBrowser]),
			...(options.modules ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig(options.origin === null ? {} : { "public-origin": options.origin ?? origin }),
			...(options.seal ? { seal: options.seal } : sealConfig()),
			...clientsConfig([
				worker("worker"),
				worker("other"),
				publicClient({
					id: "spa",
					sections: { "federation-grants": { connections: ["cal"], "return-uris": [back] } },
				}),
			]),
			...federationGrantsConfig({
				connections: {
					cal: {
						idp: "corp",
						scopes,
						"max-access-token-lifetime": "1h",
						resource: options.resource,
					},
				},
				...options.settings,
			}),
		},
		runtime,
	});
	const all = app.get(probed);
	const routeOf = (method: string, path: string) =>
		all.find(
			(r) =>
				r.method === method &&
				(r.path === path || (r.path.endsWith("/*") && path.startsWith(r.path.slice(0, -1)))),
		) as Route;

	/** Any request, to the route that answers its method and path. */
	const send = async (request: HttpRequest) =>
		read(await routeOf(request.method, request.path).handle(request));
	/** A client's call, as HTTP Basic and a JSON body. */
	const call = async (path: string, json: Record<string, unknown>, as = "worker") => {
		const basic = `Basic ${Buffer.from(`${as}:${clientSecret(as)}`).toString("base64")}`;
		const headers = new Map([["authorization", basic]]);
		return send(testRequest({ method: "POST", path, json, headers }));
	};
	/** From now on the clients answer the worker with these connections and returns. */
	const relist = (connections: string[], returns: string[]) => {
		const all = app.get(clients);
		const { find, authenticate } = all;
		const section = () => ({ connections, "return-uris": returns }) as never;
		all.find = async (id) => {
			const found = await find(id);
			return found && { ...found, section };
		};
		all.authenticate = async (request) => {
			const found = await authenticate(request);
			return found.kind === "authenticated"
				? { ...found, client: { ...found.client, section } }
				: found;
		};
	};
	const lodge = (more: Record<string, unknown> = {}, as = "worker") =>
		call(
			"/oauth/federation-grants",
			{ connection: "cal", sub: "alice", redirect_uri: back, state: "st", ...more },
			as,
		);
	const grantCall = (id: string, step: string, more: Record<string, unknown> = {}, as = "worker") =>
		call(`/oauth/federation-grants/${id}/${step}`, { sub: "alice", ...more }, as);

	/** A browser's cookie for a new session of `subject`. */
	const login = async (subject = "alice") => {
		const done = await app
			.get(sessions)
			.complete(testRequest(), { subject, amr: ["pwd"], authenticatedAt: runtime.clock.now() });
		return (done.cookies[0] ?? "").split(";")[0] ?? "";
	};
	const intents = app.get(grantIntents);
	const walk = browserStandIn(intents, {
		delegation,
		page: `${origin}/consent-page`,
		exchange: (code) => script.exchange({ code } as DelegatedExchange),
	});
	/** Opens the link a client's call answered in a browser, binding the intent to its session: the answer, and the challenge. */
	const open = async (lodged: Answer, cookie: string) => {
		const link = new URL(String(lodged.json?.connect_uri));
		const carrying = testRequest({ headers: new Map([["cookie", cookie]]) });
		const session = await app.get(sessions).enter(carrying);
		return { link, ...(await walk.open(link.searchParams.get("request") ?? "", session?.id)) };
	};
	const decide = (challenge: string, _cookie: string, decision = "accept") =>
		walk.decide(challenge, decision);

	/** Lodges an intent, and walks a browser of `subject` through the link and the question to the upstream. */
	const started = async (more: Record<string, unknown> = {}, cookie?: string) => {
		const lodged = await lodge(more);
		const id = String(lodged.json?.grant_id);
		const browser = cookie ?? (await login());
		const { opened, challenge } = await open(lodged, browser);
		const { answered, state } = await decide(challenge, browser);
		return { id, browser, lodged, opened, challenge, answered, state };
	};
	/** The upstream's return to the callback, as the browser brings it. */
	const callback = (state: string, _browser: string, code = "code-1") => walk.callback(state, code);
	/** A grant made active: the whole flow with what the upstream's exchange answers. */
	const connected = async (tokens: Partial<Record<keyof UpstreamTokens, unknown>> = {}) => {
		script.exchange = async () => upstreamLogin(upstreamTokens(tokens));
		const flow = await started();
		const done = await callback(flow.state, flow.browser);
		return { ...flow, done };
	};
	const location = (answer: Answer) => new URL(answer.headers.location ?? "", origin);

	return {
		app,
		stores,
		intents,
		script,
		asked,
		events: recorded.events,
		logs: () => logged.lines(),
		routes: all,
		send,
		relist,
		lodge,
		grantCall,
		login,
		location,
		open,
		decide,
		started,
		callback,
		connected,
		/** Before the next write of a grant, another writer changes it, and its intent, as given. */
		meanwhile: (more: object, intent: object = {}) =>
			stores.raceNext((record) => {
				const r = record as unknown as { intent: object };
				return { ...r, ...more, intent: { ...r.intent, ...intent } } as never;
			}),
		revoke: (subject: string, keepDelegations?: boolean) =>
			app
				.get(revocations)
				.record(subject, keepDelegations === undefined ? {} : { keepDelegations }),
		advance: (ms: number) => {
			now += ms;
		},
		now: () => now,
	};
}
