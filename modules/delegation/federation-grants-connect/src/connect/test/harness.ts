import { auditStandIn } from "@mod/audit/testing";
import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientSecret, clientsConfig, confidentialClient } from "@mod/clients/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import {
	type GrantsBrowser,
	grantsBrowsers,
	type StoredGrant,
	type StoredStep,
} from "@mod/federation-grants";
import federationGrants from "@mod/federation-grants/module";
import { federationGrantsConfig } from "@mod/federation-grants/testing";
import { type HttpRequest, type HttpResponse, type Route, routes } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { memoryRecords } from "@mod/records/testing";
import { type Seal, seal } from "@mod/seal";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { type EntryRequirement, entryRequirements } from "@mod/session-requirements";
import sessionRequirements from "@mod/session-requirements/module";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { roundTripStore, type StoredRoundTrip } from "@mod/upstream-round-trip";
import roundTripModule from "@mod/upstream-round-trip/module";
import {
	type DelegatedExchange,
	type Delegation,
	type DelegationStart,
	type UpstreamTokens,
	upstreams,
} from "@mod/upstreams";
import { type Users, users } from "@mod/users";
import { memoryStores } from "../../../test/stores.ts";
import connectModule from "../../module.ts";
import { name } from "../../section.ts";

export const origin = "https://issuer.example";
export const back = "https://worker.example/connected";
export const scopes = ["openid", "offline_access", "read"];

/** A seal that opens only under the context it sealed for. */
const contextSeal: Seal = {
	seal: (plain, context) => JSON.stringify([context, plain]),
	open: (sealed, context) => {
		const [bound, plain] = JSON.parse(sealed) as [string, string];
		return bound === context ? { kind: "opened", plain } : { kind: "refused" };
	},
};

/** Tokens an upstream gives, bearer with a refresh token and five minutes, unless said. */
export const upstreamTokens = (more: Readonly<Record<string, unknown>> = {}) =>
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

/** A requirement a session falls short of to be used, and at every level while `every` is set. */
export const shortToUse = (short = { every: false }): EntryRequirement => ({
	name: "mfa",
	judges: ["use", "credentials"],
	admits: async (_context, level) =>
		level === "use" || short.every
			? { kind: "short", answer: { error: "mfa_required" } }
			: { kind: "admit" },
});

export type Answer = {
	status: number;
	headers: Record<string, string>;
	json?: Record<string, unknown> | undefined;
	text?: string;
	cookies: readonly string[];
};
const read = (response: HttpResponse): Answer => {
	const body = response.body as { json?: Record<string, unknown> } | string | undefined;
	return {
		status: response.status,
		headers: { ...response.headers },
		...(typeof body === "string" ? { text: body } : { json: body?.json }),
		cookies: response.cookies ?? [],
	};
};

/** The browser half's contributions, and the routes federation-grants declares for them. */
const browsers = contract<readonly GrantsBrowser[]>("test.browsers");
const probed = contract<readonly Route[]>("test.routes");

/** What federation-grants keeps an intent and a link for, at its defaults. */
const connectMs = 600_000;
const defaultLifetimeMs = 30 * 86_400_000;
const retentionMs = 30 * 86_400_000;
const browserBase = "/session/federation-grants";

/**
 * The browser half as composed beside federation-grants, over memory stores, the session and
 * revocation stand-ins, a test upstream `corp` behind the connection `cal`, and a client `worker`
 * that may use it. `settings` are this package's section, `grants` federation-grants'. Intents are written as a lodging writes them.
 */
export async function connector(
	options: {
		readonly settings?: Readonly<Record<string, unknown>>;
		/** federation-grants' section, over the connection `cal`. */
		readonly grants?: Readonly<Record<string, unknown>>;
		readonly requirements?: readonly EntryRequirement[];
		/** Who holds which upstream account, or `down` when the users cannot say. */
		readonly holders?: Readonly<Record<string, string>>;
		readonly resource?: string;
		/** Another harness's stores, as after a restart with other settings. */
		readonly stores?: ReturnType<typeof memoryStores>;
	} = {},
) {
	let now = 1_800_000_000_000;
	const logged = recordingLog();
	const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
	const stores = options.stores ?? memoryStores(() => now, 3);
	const recorded = auditStandIn();
	const script = {
		exchange: async (_x: DelegatedExchange): Promise<unknown> => upstreamLogin(),
		startThrows: false,
		startRefused: false,
		withdrawn: false,
	};
	const asked = { starts: [] as DelegationStart[] };
	const delegation = {
		authorizationUrl: (start) => {
			if (script.startThrows) throw new Error("cannot build");
			if (script.startRefused) return { kind: "refused" };
			asked.starts.push(start);
			return `https://up.example/authorize?state=${start.state}`;
		},
		exchange: (x) => script.exchange(x) as ReturnType<Delegation["exchange"]>,
	} as Delegation;
	const holders = options.holders ?? {};
	const stubs = defineModule(
		{ name: "stubs", replicaSafe: false, takes: [grantsBrowsers, routes] },
		(m) => [
			m.provide(upstreams).by(() => ({
				of: (idp) => (idp === "corp" && !script.withdrawn ? { delegation } : undefined),
			})),
			m.provide(users).by(
				() =>
					({
						byUpstream: async (_idp: string, subject: string) => {
							const holder = holders[subject];
							if (holder === "down") throw new Unavailable("ledger");
							return holder === undefined
								? { kind: "none" }
								: { kind: "user", user: { subject: holder, attributes: {} } };
						},
					}) as unknown as Users,
			),
			m.provide(seal).by(() => contextSeal),
			...(options.requirements ?? []).map((r) => m.contribute(entryRequirements).by(() => r)),
			m.provide(browsers).by((c) => c.collect(grantsBrowsers)),
			m.provide(probed).by((c) => c.collect(routes)),
		],
	);
	const kept = memoryRecords<StoredRoundTrip>(() => runtime.clock.now(), {
		shards: 1,
		perShard: 1,
	});
	const tripStore = defineModule({ name: "trips", replicaSafe: false, takes: [] }, (m) => [
		m
			.provide(roundTripStore)
			.by(() => ({ save: kept.records.create, update: kept.records.change })),
	]);
	const app = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			cookiesModule,
			tripStore,
			roundTripModule,
			sessionStandIn,
			sessionRequirements,
			subjectRevocationStandIn,
			csrfStandIn,
			rateLimitStandIn,
			recorded.module,
			stores.module,
			stubs,
			federationGrants,
			connectModule,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": origin }),
			...clientsConfig([
				confidentialClient({
					id: "worker",
					method: "client_secret_basic",
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
				...options.grants,
			}),
			[name]: { page: `${origin}/consent-page`, ...options.settings },
		},
		runtime,
	});
	// federation-grants' own browser half would refuse boot without its page: this one answers.
	if (app.get(browsers).length !== 1) throw new Error("no browser half contributed");
	const all = app.get(probed);
	const routeOf = (method: string, path: string) =>
		all.find(
			(r) =>
				r.method === method &&
				(r.path === path || (r.path.endsWith("/*") && path.startsWith(r.path.slice(0, -1)))),
		) as Route;
	const send = async (request: HttpRequest) =>
		read(await routeOf(request.method, request.path).handle(request));
	/** A client's call, as HTTP Basic and a JSON body. */
	const grantCall = (id: string, step: string, more: Record<string, unknown> = {}) => {
		const basic = `Basic ${Buffer.from(`worker:${clientSecret("worker")}`).toString("base64")}`;
		const headers = new Map([["authorization", basic]]);
		const path = `/oauth/federation-grants/${id}/${step}`;
		return send(testRequest({ method: "POST", path, json: { sub: "alice", ...more }, headers }));
	};
	/** From now on the clients answer the worker with these connections and returns. */
	const relist = (connections: string[], returns: string[]) => {
		const found = app.get(clients);
		const { find } = found;
		const section = () => ({ connections, "return-uris": returns }) as never;
		found.find = async (id) => {
			const client = await find(id);
			return client && { ...client, section };
		};
	};

	let n = 0;
	/** A pending grant of `alice` for `worker` at `cal`, with its intent and its link, as a lodging writes them. */
	const lodge = async (more: Readonly<Record<string, unknown>> = {}) => {
		n++;
		const intent = {
			id: `intent-${n}`,
			kind: "initial",
			returnUri: back,
			state: "st",
			scopes,
			lifetimeMs: defaultLifetimeMs,
			startedAt: now,
			endsAt: now + connectMs,
			...more,
		};
		const grant = {
			format: 1,
			id: `grant-${n}`,
			client: "worker",
			subject: "alice",
			connection: "cal",
			status: "pending",
			createdAt: now,
			scopes: intent.scopes,
			intent,
			version: `v-${n}`,
			rotations: { from: now, count: 0 },
		};
		await stores.grants.create(grant.id, grant as unknown as StoredGrant, connectMs + retentionMs);
		const link = `link-${grant.id}`;
		const step = { format: 1, kind: "link", grant: grant.id, intent: intent.id };
		await stores.steps.create(link, step as unknown as StoredStep, connectMs);
		await stores.subjects.add(grant.subject, grant.id, connectMs);
		return { id: grant.id, link };
	};

	/** A browser's cookie for a new session of `subject`. */
	const login = async (subject = "alice") => {
		const done = await app
			.get(sessions)
			.complete(testRequest(), { subject, amr: ["pwd"], authenticatedAt: runtime.clock.now() });
		return (done.cookies[0] ?? "").split(";")[0] ?? "";
	};
	/** A browser's request to a route, with its cookie and its query or form. */
	const browse = (
		method: "GET" | "POST",
		path: string,
		cookie: string,
		params: Record<string, string | readonly string[]> = {},
	) => {
		const values = new Map(
			Object.entries(params).map(([k, v]) => [k, typeof v === "string" ? [v] : [...v]]),
		);
		return send(
			testRequest({
				method,
				path,
				headers: new Map([["cookie", cookie]]),
				...(method === "POST" ? { form: values } : { query: values }),
			}),
		);
	};
	const paths = {
		connect: ["GET", `${browserBase}/connect`],
		question: ["GET", `${browserBase}/consent`],
		decide: ["POST", `${browserBase}/consent`],
	} as const;
	/** A browser's request to one of the steps, with its cookie and its query or form. */
	const step = (
		name: "connect" | "question" | "decide" | "callback",
		cookie: string,
		params: Record<string, string | readonly string[]> = {},
		path = `${browserBase}/callback/cal`,
	) =>
		name === "callback"
			? browse("GET", path, cookie, params)
			: browse(paths[name][0], paths[name][1], cookie, params);
	const location = (answer: Answer) => new URL(answer.headers.location ?? "", origin);

	/** Opens a link, or the one a client's call answered, in a browser: the answer, and the challenge it carries. */
	const open = async (target: string | Answer, cookie: string) => {
		const link =
			typeof target === "string"
				? new URL(`${origin}${browserBase}/connect?request=${target}`)
				: new URL(String(target.json?.connect_uri));
		const opened = await step("connect", cookie, {
			request: link.searchParams.get("request") ?? "",
		});
		return { link, opened, challenge: location(opened).searchParams.get("challenge") ?? "" };
	};
	/** The round trip's cookie each browser holds, by its session cookie, as a browser keeps the last set. */
	const jar = new Map<string, string>();
	/** Decides a challenge in a browser: the answer, and the upstream state it carries. */
	const decide = async (challenge: string, cookie: string, decision = "accept") => {
		const answered = await step("decide", cookie, { challenge, decision });
		const set = answered.cookies.find((c) => c.includes("federation-grants."));
		if (set) jar.set(cookie, set.split(";")[0] ?? "");
		return { answered, state: location(answered).searchParams.get("state") ?? "" };
	};
	/** Lodges an intent, and walks a browser of `alice` through the link and the question to the upstream. */
	const started = async (more: Readonly<Record<string, unknown>> = {}, cookie?: string) => {
		const { id, link } = await lodge(more);
		const browser = cookie ?? (await login());
		const { opened, challenge } = await open(link, browser);
		const { answered, state } = await decide(challenge, browser);
		return { id, link, browser, opened, challenge, answered, state };
	};
	/** The upstream's return to the callback, as the browser brings it. */
	const callback = (
		state: string,
		browser: string,
		query: Record<string, readonly string[]> = {},
	) =>
		step("callback", [browser, jar.get(browser) ?? ""].filter(Boolean).join("; "), {
			state: [state],
			code: ["code-1"],
			...query,
		});
	/** A grant made active: the whole flow with what the upstream's exchange answers. */
	const connected = async (tokens: Readonly<Record<string, unknown>> = {}) => {
		script.exchange = async () => upstreamLogin(upstreamTokens(tokens));
		const flow = await started();
		const done = await callback(flow.state, flow.browser);
		return { ...flow, done };
	};

	return {
		app,
		stores,
		/** The round trips kept, by their cookie's value. */
		trips: kept.records,
		script,
		asked,
		events: recorded.events,
		logs: () => logged.lines(),
		relist,
		revoke: (who = "alice") => app.get(revocations).record(who),
		grantCall,
		lodge,
		login,
		browse,
		step,
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
		now: () => now,
		advance: (ms: number) => {
			now += ms;
		},
	};
}
