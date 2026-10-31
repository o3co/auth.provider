import { auditStandIn } from "@mod/audit/testing";
import claimsSelection from "@mod/claims-selection/module";
import { claimsSelectionInMemory } from "@mod/claims-selection/testing";
import { type Clients, clients, metadataSections } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, publicClient } from "@mod/clients/testing";
import { sessionRedemptions } from "@mod/code-grant";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { type HttpResponse, listening, type Route, routes } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, contract, defineModule, kernelConfig, type Module } from "@mod/kernel";
import {
	quietRuntime,
	recordingLog,
	switchedModule,
	type UnavailableSwitch,
} from "@mod/kernel/testing";
import { keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import oidc from "@mod/oidc/module";
import { type Outbound, type OutboundRequest, outbound } from "@mod/outbound";
import { outboundRefusals } from "@mod/outbound-policy";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { redirects } from "@mod/redirect-uris";
import secretHashModule from "@mod/secret-hash/module";
import { sessions } from "@mod/session";
import { sessionStandIn, stubSessions } from "@mod/session/testing";
import { participants } from "@mod/session-participants";
import sessionParticipants from "@mod/session-participants/module";
import sessionRequirements from "@mod/session-requirements/module";
import subjectAttributes from "@mod/subject-attributes/module";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import usersModule from "@mod/users/module";
import { memoryUsersStores, usersConfig } from "@mod/users/testing";
import { afterEach } from "vitest";
import rpLogout from "../src/module.ts";
import { type SessionClients, sessionClients } from "../src/store.ts";
import { type RpLogoutSettings, rpLogoutConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

/** What a request to a route answered, as the tests read it. */
export interface Called {
	readonly status: number | undefined;
	readonly headers: Readonly<Record<string, string>>;
	readonly cookies: readonly string[];
	readonly loads: HttpResponse["loads"];
	readonly json: Record<string, unknown> | undefined;
	readonly text: string | undefined;
}

export const issuer = "https://as.example";
export const back = "https://app.example/after";

/** A request the outside sent, and how the stand-in answered it. */
export interface Sent {
	readonly url: string;
	readonly request: OutboundRequest | undefined;
}

const probed = contract<{
	readonly routes: readonly Route[];
	readonly items: readonly MetadataItem[];
	readonly redeemed: (session: string, client: string) => Promise<void>;
}>("test.probed");

/**
 * rp-logout composed with oidc, keys and clients, a session stand-in, its stores in memory, and an
 * outbound stand-in that answers each request as `answer` says.
 */
export async function harness(
	options: {
		readonly settings?: Partial<RpLogoutSettings>;
		readonly sections?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
		/** Each client's redirect URIs, by id; `https://app.example/cb` for one not named. */
		readonly redirects?: Readonly<Record<string, readonly string[]>>;
		readonly extra?: readonly Module[];
		/** Leaves `http`'s public origin unwritten: the issuer alone names this provider. */
		readonly noPublicOrigin?: true;
		readonly sessionsModule?: Module;
		/** `csrf` as an app composes it, in place of its stand-in. */
		readonly csrfModule?: Module;
		/** Makes rp-logout's session clients store fail as it says. */
		readonly clientsDown?: UnavailableSwitch<SessionClients>;
		/** Makes the client records fail as it says. */
		readonly clientRecordsDown?: UnavailableSwitch<Clients>;
		/** Why outbound's destination policy refuses a URL, as its refusals explain it; none by default. */
		readonly refused?: (url: string) => string | undefined;
	} = {},
) {
	let now = 1_800_000_000_000;
	const logged = recordingLog();
	const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
	const stores = memoryStores(() => now);
	const recorded = auditStandIn();
	const sent: Sent[] = [];
	const answering = { answer: async (_url: string): Promise<number> => 200 };
	const outside = defineModule(
		{ takes: [], name: "outbound-stand-in", replicaSafe: false },
		(m) => [
			m.provide(outboundRefusals).by(() => ({ explained: (url) => options.refused?.(url) })),
			m.provide(outbound).by(
				(): Outbound => ({
					fetch: async (url, request) => {
						sent.push({ url, request });
						const status = await answering.answer(url);
						return { status, headers: new Map(), body: new Uint8Array() };
					},
				}),
			),
		],
	);
	const reader = defineModule(
		{ takes: [sessionRedemptions, routes, metadata], name: "reader", replicaSafe: true },
		(m) => [
			m.provide(probed).by(async (c) => {
				const [redemption] = await c.collect(sessionRedemptions);
				return {
					routes: await c.collect(routes),
					items: await c.collect(metadata),
					redeemed: (session, client) => redemption?.redeemed(session, client) ?? Promise.resolve(),
				};
			}),
		],
	);
	const registered = Object.entries(
		options.sections ?? {
			app: {
				"post-logout-redirect-uris": [back],
				"backchannel-logout-uri": "https://app.example/bc",
				"frontchannel-logout-uri": "https://app.example/fc",
			},
		},
	).map(([id, section]) =>
		publicClient({
			id,
			sections: {
				"rp-logout": section,
				authorize: { "redirect-uris": options.redirects?.[id] ?? ["https://app.example/cb"] },
			},
		}),
	);
	// redirect-uris' section, which the front-channel URL is judged against; authorize is not composed.
	const redirectsSection = defineModule(
		{ takes: [], name: "authorize-section", replicaSafe: true },
		(m) => [m.contribute(metadataSections).by(() => redirects)],
	);
	const app = await assemble({
		modules: [
			http,
			keysModule,
			issuerModule,
			memoryUsersStores().module,
			usersModule,
			secretHashModule,
			// oidc reads the selection a code's redemption pinned; these ID tokens name none.
			claimsSelection,
			claimsSelectionInMemory().module,
			oidc,
			subjectAttributes,
			options.clientRecordsDown
				? switchedModule(clientsModule, clients, options.clientRecordsDown)
				: clientsModule,
			redirectsSection,
			cookiesModule,
			options.csrfModule ?? csrfStandIn,
			options.sessionsModule ?? sessionStandIn,
			sessionRequirements,
			sessionParticipants,
			subjectRevocationStandIn,
			recorded.module,
			options.clientsDown
				? switchedModule(stores.module, sessionClients, options.clientsDown)
				: stores.module,
			outside,
			rateLimitStandIn,
			rpLogout,
			reader,
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig({
				...(options.noPublicOrigin ? {} : { "public-origin": issuer }),
				// `served` reaches http on loopback, as the issuer's https origin behind a proxy.
				"trusted-proxies": ["127.0.0.1"],
			}),
			...keysConfig(),
			...issuerConfig({ url: issuer }),
			...usersConfig([]),
			...clientsConfig(registered),
			...rpLogoutConfig({ "sweep-interval": "1s", ...options.settings }),
		},
		runtime,
	});
	await app.start();
	const seen = app.get(probed);
	/** A session for the subject, with the cookie that opens it. */
	const login = async (subject = "alice") => {
		const done = await app
			.get(sessions)
			.complete(testRequest(), { subject, amr: ["pwd"], authenticatedAt: runtime.clock.now() });
		return { session: done.session, cookie: (done.cookies[0] ?? "").split(";")[0] ?? "" };
	};
	/** An ID token for the session, as oidc makes it, the claims written over by `over`. */
	const hintFor = (session: string, over: Record<string, unknown> = {}) => {
		const iat = Math.floor(now / 1000);
		return app.get(keys).sign(
			{
				iss: issuer,
				sub: "alice",
				aud: "app",
				azp: "app",
				iat,
				exp: iat + 3600,
				sid: session,
				...over,
			},
			"JWT",
		);
	};
	/**
	 * A request to the logout. A `303` on to the logout's own `GET`, as a hinted `POST` answers, is
	 * followed with the same headers, as a browser follows it, unless `follow` is false.
	 */
	const call = async (
		method: "GET" | "POST",
		/** Each parameter's value, or its values where it is sent more than once. */
		params: Record<string, string | readonly string[]>,
		headers: Record<string, string> = {},
		follow = true,
	): Promise<Called> => {
		const called = await once(method, params, headers);
		const location = called.headers.location;
		if (!follow || called.status !== 303 || !location?.startsWith("/oauth/logout?")) return called;
		const query = Object.fromEntries(new URL(location, issuer).searchParams);
		return call("GET", query, headers, follow);
	};
	const once = async (
		method: "GET" | "POST",
		params: Record<string, string | readonly string[]>,
		headers: Record<string, string>,
	) => {
		const route = seen.routes.find((r) => r.path === "/oauth/logout" && r.method === method);
		const values = new Map(
			Object.entries(params).map(([k, v]) => [k, typeof v === "string" ? [v] : [...v]]),
		);
		const response: HttpResponse | undefined = await route?.handle(
			testRequest({
				method,
				path: "/oauth/logout",
				headers: new Map(Object.entries(headers)),
				...(method === "GET" ? { query: values } : { form: values }),
			}),
		);
		const body = response?.body;
		const json =
			typeof body === "object" && body !== null && "json" in body ? body.json : undefined;
		return {
			status: response?.status,
			headers: response?.headers ?? {},
			cookies: response?.cookies ?? [],
			loads: response?.loads,
			json: json as Record<string, unknown> | undefined,
			text: typeof body === "string" ? body : undefined,
		};
	};
	/**
	 * A request through http itself, on its port: for what http alone answers, as Unavailable. It
	 * comes through the trusted proxy for a browser at one address, a POST from the issuer's own
	 * pages; a `303` on to the logout's own `GET` is followed with the same headers, as `call` does.
	 */
	const served = async (
		method: "GET" | "POST",
		path: string,
		params: Record<string, string>,
		headers: Record<string, string> = {},
	): Promise<{ status: number; cacheControl: string | null; json: unknown }> => {
		const url = new URL(path, `http://127.0.0.1:${app.get(listening).port()}`);
		const form = new URLSearchParams(params);
		if (method === "GET") url.search = form.toString();
		const res = await fetch(url, {
			method,
			redirect: "manual",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": "203.0.113.7",
				...(method === "POST" ? { origin: issuer } : {}),
				...headers,
			},
			...(method === "POST" ? { body: form } : {}),
		});
		const location = res.headers.get("location");
		if (res.status === 303 && location?.startsWith("/oauth/logout?")) {
			await res.body?.cancel();
			const query = Object.fromEntries(new URL(location, issuer).searchParams);
			return served("GET", "/oauth/logout", query, headers);
		}
		const text = await res.text();
		const json = res.headers.get("content-type")?.startsWith("application/json")
			? JSON.parse(text)
			: undefined;
		return { status: res.status, cacheControl: res.headers.get("cache-control"), json };
	};
	/** A request to the confirmation's routes, as `call` makes one to the logout's. */
	const confirming = async (
		method: "GET" | "POST",
		fields: Record<string, string>,
		headers: Record<string, string> = {},
	) => {
		const route = seen.routes.find(
			(r) => r.path === "/oauth/logout/confirm" && r.method === method,
		);
		const values = new Map(Object.entries(fields).map(([k, v]) => [k, [v]]));
		const response = await route?.handle(
			testRequest({
				method,
				path: "/oauth/logout/confirm",
				headers: new Map(Object.entries(headers)),
				...(method === "GET" ? { query: values } : { form: values }),
			}),
		);
		return {
			status: response?.status,
			headers: response?.headers ?? {},
			cookies: response?.cookies ?? [],
			loads: response?.loads,
			text: typeof response?.body === "string" ? response.body : undefined,
		};
	};
	return {
		app,
		stores,
		confirming,
		events: recorded.events,
		logs: logged.lines,
		sent,
		answering,
		items: seen.items,
		routes: seen.routes,
		redeemed: seen.redeemed,
		login,
		hintFor,
		call,
		served,
		advance: (ms: number) => {
			now += ms;
		},
		/** Whether the session enters at use. */
		stillOpen: async (session: string) =>
			(await app.get(sessions).entryOf(session)).kind === "entered",
		stop: () => app.stop(1000),
	};
}

export type Harness = Awaited<ReturnType<typeof harness>>;

/** Starts harnesses for a file's tests, each stopped after the test that started it. */
/**
 * Sessions that a read ends once past `lifetimeMs`, and whose close still finds the record open, as
 * the lifecycle's do; a browser's cookie `session=<id>` names its session's handle.
 */
export function readEndingSessions(lifetimeMs: number) {
	return defineModule({ takes: [participants], name: "session", replicaSafe: false }, (m) => [
		m.provide(sessions).by(async (c) => {
			const closers = await c.collect(participants);
			type Kept = { subject: string; openedAt: number; state: "open" | "closing" | "closed" };
			const kept = new Map<string, Kept>();
			const sessionOf = (id: string, r: Kept) => ({
				id,
				context: { subject: r.subject, amr: ["pwd"], authenticatedAt: r.openedAt },
			});
			return stubSessions({
				handleOf: async (request) => {
					const id = /session=([^;]+)/.exec(request.headers.get("cookie") ?? "")?.[1];
					return id !== undefined && kept.has(id) ? id : undefined;
				},
				complete: async (_request, facts) => {
					const id = `s${kept.size + 1}`;
					const r: Kept = { subject: facts.subject, openedAt: c.clock.now(), state: "open" };
					kept.set(id, r);
					return { session: sessionOf(id, r), cookies: [`session=${id}`] };
				},
				entryOf: async (id) => {
					const r = kept.get(id);
					if (r?.state !== "open") return { kind: "absent" };
					if (r.openedAt + lifetimeMs <= c.clock.now()) {
						r.state = "closed";
						return { kind: "absent" };
					}
					return { kind: "entered", session: sessionOf(id, r), endsAt: r.openedAt + lifetimeMs };
				},
				close: async (id) => {
					const r = kept.get(id);
					if (!r) return { kind: "closed", cookies: [] };
					const from = r.state;
					if (r.state !== "closed") {
						r.state = "closing";
						for (const closer of closers) await closer.closing(sessionOf(id, r));
						r.state = "closed";
					}
					return { kind: "closed", cookies: [], session: { id, subject: r.subject }, from };
				},
			});
		}),
	]);
}

export function servedEach() {
	const started: Harness[] = [];
	afterEach(async () => {
		await Promise.all(started.splice(0).map((h) => h.stop()));
	});
	return async (options: Parameters<typeof harness>[0] = {}) => {
		const h = await harness(options);
		started.push(h);
		return h;
	};
}

/** The notices kept, without settling any: `each` keeps every notice whose handling throws. */
export async function keptNotices(h: Harness) {
	const found: string[] = [];
	await h.stores.notices.each(async (notice) => {
		found.push(notice);
		throw new Error("only listing");
	});
	return found;
}

/** Waits until no notice is kept, for up to `ms`; a sweep runs every second here. */
export async function settled(h: Harness, ms = 5000) {
	for (let i = 0; i < ms / 50 && (await keptNotices(h)).length > 0; i++) {
		await new Promise((r) => setTimeout(r, 50));
	}
}

/** Waits until `ready` holds, for up to `ms`. */
export async function until(ready: () => boolean, ms = 2000) {
	for (let i = 0; i < ms / 10 && !ready(); i++) await new Promise((r) => setTimeout(r, 10));
}
