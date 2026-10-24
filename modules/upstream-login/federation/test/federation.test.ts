import { createHash } from "node:crypto";
import { auditStandIn } from "@mod/audit/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import linkModule from "@mod/federation-link/module";
import { listening, type Route, requestEnds, routes } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { loginSource } from "@mod/login-attributes";
import { type LoginFrom, loginGates, logins, openedAfterHold, returnPaths } from "@mod/login-gates";
import gatesModule from "@mod/login-gates/module";
import rateLimitModule from "@mod/rate-limit/module";
import { memoryRecords } from "@mod/records/testing";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import secretHashModule from "@mod/secret-hash/module";
import { type LoginFacts, type Session, sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { heldLoginStore, type StoredHeldLogin } from "@mod/upstream-handoff";
import handoffModule from "@mod/upstream-handoff/module";
import handoffSealModule from "@mod/upstream-handoff-seal/module";
import { roundTripStore, type StoredRoundTrip } from "@mod/upstream-round-trip";
import roundTripModule from "@mod/upstream-round-trip/module";
import {
	type Delegation,
	idpType,
	type Upstream,
	type UpstreamLogin,
	type UpstreamTokens,
	upstreamLoginReceivers,
	upstreams,
} from "@mod/upstreams";
import { upstreamNames } from "@mod/users";
import usersModule from "@mod/users/module";
import { memoryUsersStores, testUser, usersConfig } from "@mod/users/testing";
import { afterEach, beforeEach, describe, expect, expectTypeOf, it } from "vitest";
import { z } from "zod";
import federationModule from "../src/module.ts";
import { section } from "../src/section.ts";
import { federationConfig, testIdpType } from "../src/testing.ts";

/** The time every test starts at; a test that moves the clock moves it only for itself. */
const start = 1_800_000_000_000;
let now = start;
const recorded = recordingLog();
/** Where this test's lines begin in the log, which runs on across tests. */
let logStart = 0;
const runtime = quietRuntime({ clock: { now: () => now }, log: recorded.log });
/** This test's warn and error lines so far, as the event and its fields in JSON. */
const logged = () =>
	recorded
		.lines()
		.slice(logStart)
		.filter((line) => line.level !== "info")
		.map((line) => `${line.event} ${JSON.stringify(line.fields)}`);
let stop = async () => {};
beforeEach(() => {
	now = start;
	logStart = recorded.lines().length;
});
afterEach(() => stop());

const origin = "https://as.example";
const base = "/session/oauth/federation";
const alice: UpstreamLogin = { subject: "u-alice", amr: ["mfa"], authenticatedAt: start };
/** How far behind ours the test IdP type lets an upstream's clock be. */
const skewMs = 30_000;
/** Headers as the trusted proxy forwards a request over https. */
const viaProxy = { "x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.1" };

type Answer = UpstreamLogin | "unreachable" | "broken" | "copied";
/** What the test type's upstream answers for each code. */
const answering = (...pairs: (readonly [string, Answer])[]) => new Map<string, Answer>(pairs);
/** An upstream login of alice, made at `ms`. */
const aliceAt = (ms: number): UpstreamLogin => ({
	subject: "u-alice",
	amr: [],
	authenticatedAt: ms,
});
/** The cookie as a response clearing it sets it, its name with no value. */
const clearedOf = (cookie: string) => cookie.replace(/=.*/, "=");

/** What a test request sends besides its path and cookie. */
interface Sent {
	readonly method?: string;
	readonly headers?: Record<string, string>;
	readonly body?: string;
}

interface Setup {
	readonly federation?: Record<string, unknown>;
	readonly extra?: Module[];
	readonly answers?: Map<string, Answer>;
	/** In place of the held logins' store. */
	readonly held?: Module;
	/** In place of the round trips' store. */
	readonly trips?: Module;
	readonly origin?: string | null;
	/** Modules that receive upstream tokens; seal comes with them. */
	readonly receivers?: Module[];
	/** Leaves csrf out, whose origin evidence a start and a link need. */
	readonly withoutCsrf?: true;
	/** Gives alice no upstream identity, as a deployment with no IdP has none to name. */
	readonly unlinked?: true;
	/** Leaves out the link, which the bridge brings beside federation in a composed app. */
	readonly withoutLink?: true;
	/** What the test type's upstreams offer besides a login. */
	readonly more?: Pick<Upstream, "refresh" | "endSession" | "delegation">;
}

async function serve(setup: Setup = {}) {
	const idp = testIdpType(setup.answers ?? answering(["good", alice]), setup.more);
	const saved: string[] = [];
	const keptHeld = memoryRecords<StoredHeldLogin>(() => now, { shards: 1, perShard: 1 });
	const held = defineModule({ name: "held" }, (m) => [
		m.provide(heldLoginStore).by(() => ({
			save: async (key, value, lifetimeMs) => {
				saved.push(JSON.stringify(value));
				return keptHeld.records.create(key, value, lifetimeMs);
			},
			update: keptHeld.records.change,
			remove: keptHeld.records.remove,
		})),
	]);
	const keptTrips = memoryRecords<StoredRoundTrip>(() => now, { shards: 1, perShard: 1 });
	const trips = defineModule({ name: "trips" }, (m) => [
		m.provide(roundTripStore).by(() => ({
			save: async (key, value, lifetimeMs) => {
				saved.push(JSON.stringify(value));
				return keptTrips.records.create(key, value, lifetimeMs);
			},
			update: keptTrips.records.change,
		})),
	]);
	const receiving = setup.receivers ?? [];
	const audit = auditStandIn();
	const app = await assemble({
		modules: [
			http,
			...(setup.withoutCsrf ? [] : [csrfStandIn]),
			cookiesModule,
			gatesModule,
			usersModule,
			secretHashModule,
			memoryUsersStores().module,
			sessionStandIn,
			subjectRevocationStandIn,
			rateLimitModule,
			audit.module,
			simulatedStore().module,
			federationModule,
			...(setup.withoutLink ? [] : [linkModule]),
			idp.module,
			handoffModule,
			setup.held ?? held,
			roundTripModule,
			setup.trips ?? trips,
			...(setup.extra ?? []),
			...(receiving.length > 0 ? [sealModule, handoffSealModule, ...receiving] : []),
		],
		config: {
			...kernelConfig(),
			...(receiving.length > 0 ? sealConfig() : {}),
			...httpConfig({
				"trusted-proxies": ["127.0.0.1"],
				...(setup.origin === null ? {} : { "public-origin": setup.origin ?? origin }),
				...(setup.origin?.startsWith("http:") ? { "insecure-origin": true } : {}),
			}),
			...usersConfig([
				testUser("alice", "pw", {
					upstream: setup.unlinked ? [] : [{ idp: "corp", subject: "u-alice" }],
				}),
			]),
			...federationConfig({
				idps: { corp: { type: "test", issuer: "https://idp.example" } },
				...setup.federation,
			}),
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const at = `http://127.0.0.1:${app.get(listening).port()}`;
	/** Sends a request through the proxy, and answers the cookies it set by name and value only. */
	const send = async (path: string, cookie: string, init: Sent = {}) => {
		const res = await fetch(`${at}${path}`, {
			...init,
			redirect: "manual",
			headers: { ...viaProxy, ...(cookie ? { cookie } : {}), ...init.headers },
		});
		const text = await res.text();
		return {
			status: res.status,
			location: res.headers.get("location") ?? "",
			cookies: res.headers.getSetCookie().map((c) => c.split(";")[0] ?? ""),
			body: text.startsWith("{") ? JSON.parse(text) : text,
		};
	};
	const get = (path: string, cookie = "", more: Record<string, string> = {}) =>
		send(path, cookie, { headers: more });
	/** Starts a login, and answers the state it sent upstream and the cookie it set. */
	const begin = async (query = "") => {
		const started = await get(`${base}/corp${query}`);
		const state = started.location
			? (new URL(started.location).searchParams.get("state") ?? "")
			: "";
		return {
			...started,
			state,
			cookie: started.cookies.find((c) => c.includes("federation.corp")) ?? "",
		};
	};
	const callback = (query: string, cookie: string) => get(`${base}/corp/callback?${query}`, cookie);
	/** Begins a login with `query`, and comes back with `answer`, as the upstream sends the browser. */
	const roundTrip = async (answer: string, query = "") => {
		const started = await begin(query);
		return { ...(await callback(`${answer}&state=${started.state}`, started.cookie)), started };
	};
	/** Posts a form to a path, as an upstream answering in form_post sends the browser back. */
	const post = (path: string, form: string, cookie = "") =>
		send(path, cookie, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: form,
		});
	const contextOf = async (cookies: readonly string[]) => {
		const request = testRequest({ headers: new Map([["cookie", cookies.join("; ")]]) });
		return (await app.get(sessions).enter(request))?.context;
	};
	const amrOf = async (cookies: readonly string[]) => (await contextOf(cookies))?.amr;
	const achievable = async (amr: readonly string[]) => (await app.get(logins)).achievable(amr);
	/** Goes on with a login the gate held, as that gate would once its step is done. */
	const resume = async (held: Held, facts = held.facts) =>
		(await app.get(logins)).resume(testRequest(), facts, "second", held.done, held.from);
	/** Logs in through the gates for another caller, as a different way of logging in would. */
	const login = async (from: LoginFrom) => {
		const facts = { subject: "alice", amr: ["pwd"], authenticatedAt: runtime.clock.now() };
		return (await app.get(logins)).login(testRequest(), facts, {}, from);
	};
	return {
		saved,
		declared: <T>(of: ReturnType<typeof contract<T>>) => app.get(of),
		resume,
		login,
		upstreams: () => app.get(upstreams),
		at,
		get,
		post,
		begin,
		callback,
		roundTrip,
		amrOf,
		contextOf,
		achievable,
		asked: idp.asked,
		events: audit.events,
	};
}

describe("federation", () => {
	it("links only on a start asking it by 1 or true, which a page of no origin cannot; any other value logs in", async () => {
		const s = await serve();
		for (const asked of ["1", "true"]) {
			const started = await s.begin(`?link=${asked}`);
			expect([asked, started.status, started.body], asked).toEqual([
				asked,
				403,
				{ error: "link_requires_trusted_origin" },
			]);
		}
		expect((await s.begin("?link=yes")).status).toBe(302);
	});

	it("takes a login's start from another site's navigation, binding its state to the cookie it sets", async () => {
		const s = await serve();
		const kept = s.saved.length;
		const started = await s.get(`${base}/corp`, "", { "sec-fetch-site": "cross-site" });
		expect(started.status).toBe(302);
		expect(s.saved.length).toBe(kept + 1);
		expect(started.cookies.filter((c) => c.includes("federation.corp"))).toHaveLength(1);
	});

	it("goes on with the browser's live login round trip on a start from another site, or one that says nothing of its site", async () => {
		const s = await serve({ federation: { "transaction-lifetime": "1m" } });
		const first = await s.begin("?prompt=login&max_age=60");
		const kept = s.saved.length;
		const sites = [{ "sec-fetch-site": "cross-site" }, { "sec-fetch-site": "same-site" }, {}];
		for (const site of sites) {
			const again = await s.get(`${base}/corp`, first.cookie, site);
			// The same request upstream as the first start's, whatever this one asked; no cookie, nothing kept.
			expect([again.status, again.location, again.cookies], JSON.stringify(site)).toEqual([
				302,
				first.location,
				[],
			]);
		}
		expect(s.saved.length).toBe(kept);
		// Each the first start's request whole: its state, nonce, challenge, prompt and max age.
		const [asked, ...again] = s.asked.starts;
		expect(asked).toMatchObject({ prompt: "login", maxAgeSeconds: 60 });
		expect(again).toEqual(sites.map(() => asked));
		// Read, it is not lengthened: it ends where the first start put it.
		now += 30_000;
		const answered = await s.callback(`code=good&state=${first.state}`, first.cookie);
		expect(answered.status).toBe(302);
		// A link from another site is still refused before anything else.
		const linking = await s.get(`${base}/corp?link=1`, first.cookie, {
			"sec-fetch-site": "cross-site",
		});
		expect(linking.status).toBe(403);
	});

	it("goes on with a link's live round trip on a login's start from another site, which ends in the link", async () => {
		const s = await serve();
		const first = await s.begin();
		const loggedIn = await s.callback(
			`code=good&state=${first.state}&iss=https://idp.example`,
			first.cookie,
		);
		const session = loggedIn.cookies.filter((c) => !c.includes("federation.corp=")).join("; ");
		const linking = await s.get(`${base}/corp?link=1`, session, {
			"sec-fetch-site": "same-origin",
		});
		const cookie = linking.cookies.find((c) => c.includes("federation.corp")) ?? "";
		const again = await s.get(`${base}/corp`, `${session}; ${cookie}`, {
			"sec-fetch-site": "cross-site",
		});
		expect([again.status, again.location, again.cookies]).toEqual([302, linking.location, []]);
		const state = new URL(linking.location).searchParams.get("state") ?? "";
		const before = s.events.length;
		await s.callback(`code=good&state=${state}&iss=https://idp.example`, `${session}; ${cookie}`);
		expect(s.events.slice(before).map((e) => e.kind)).not.toContain("federation.login.succeeded");
	});

	it("begins anew where the browser's live round trip carries what federation does not read", async () => {
		const kept = memoryRecords<StoredRoundTrip>(() => now, { shards: 1, perShard: 1 });
		let garbled = false;
		const trips = defineModule({ name: "trips" }, (m) => [
			m.provide(roundTripStore).by(() => ({
				save: kept.records.create,
				update: async (key, change) => {
					const read = await kept.records.change(key, change);
					if (!garbled || !read) return read;
					const odd = { ...(read.before as object), carried: { unheard: 1 } } as never;
					return { before: odd, after: odd };
				},
			})),
		]);
		const s = await serve({ trips });
		const first = await s.begin();
		garbled = true;
		const again = await s.get(`${base}/corp`, first.cookie, { "sec-fetch-site": "cross-site" });
		expect(new URL(again.location).searchParams.get("state")).not.toBe(first.state);
		expect(again.cookies.filter((c) => c.includes("federation.corp"))).toHaveLength(1);
	});

	describe("a round trip an earlier version wrote, carrying a link's session as its own field", () => {
		/**
		 * A round trip store writing each record in that earlier shape: a link's session as `link`, a
		 * login's with none; `forced` gives a login's one too, and `mixed` keeps the name beside it.
		 */
		const earlier = ({ mixed = false, forced = false } = {}) => {
			const kept = memoryRecords<StoredRoundTrip>(() => now, { shards: 1, perShard: 1 });
			return defineModule({ name: "trips" }, (m) => [
				m.provide(roundTripStore).by(() => ({
					save: async (key, value, lifetimeMs) => {
						const { carried: was, ...rest } = value as unknown as {
							carried: { by?: string; kept?: unknown };
						};
						const { by, kept: link, ...left } = was;
						const old =
							by !== undefined || forced
								? { ...left, link: link ?? { session: "s-old", subject: "alice" } }
								: left;
						if (mixed) Object.assign(old, { by: "link" });
						return kept.records.create(key, { ...rest, carried: old } as never, lifetimeMs);
					},
					update: kept.records.change,
				})),
			]);
		};
		/** A session of alice's, and a link begun from it, as the earlier version kept it. */
		const linkStarted = async (s: Awaited<ReturnType<typeof serve>>) => {
			const first = await s.begin();
			const loggedIn = await s.callback(
				`code=good&state=${first.state}&iss=https://idp.example`,
				first.cookie,
			);
			const session = loggedIn.cookies.filter((c) => !c.includes("federation.corp=")).join("; ");
			const linking = await s.get(`${base}/corp?link=1`, session, {
				"sec-fetch-site": "same-origin",
			});
			const state = new URL(linking.location).searchParams.get("state") ?? "";
			const cookie = linking.cookies.find((c) => c.includes("federation.corp")) ?? "";
			return { session, linking, state, cookie: `${session}; ${cookie}` };
		};

		it("ends in the link, and a start from another site goes on with it", async () => {
			const s = await serve({ trips: earlier() });
			const { linking, state, cookie } = await linkStarted(s);
			const again = await s.get(`${base}/corp`, cookie, { "sec-fetch-site": "cross-site" });
			expect([again.status, again.location, again.cookies]).toEqual([302, linking.location, []]);
			const before = s.events.length;
			const back = await s.callback(`code=good&state=${state}&iss=https://idp.example`, cookie);
			// Alice holds that identity already: it ends in the link, which records nothing for it, never a login.
			expect(back.status).toBe(302);
			expect(s.events.slice(before).filter((e) => e.kind.startsWith("federation.login."))).toEqual(
				[],
			);
		});

		it("is refused, warned, where no link is composed, and refused as a round trip it cannot read where it mixes both shapes", async () => {
			const s = await serve({ trips: earlier({ forced: true }), withoutLink: true });
			const started = await s.begin();
			const back = await s.callback(`code=good&state=${started.state}`, started.cookie);
			expect([back.status, back.body]).toEqual([400, { error: "continuation_unavailable" }]);
			expect(logged()).toContain('federation.continuation_missing {"idp":"corp","name":"link"}');
			const mixed = await serve({ trips: earlier({ mixed: true, forced: true }) });
			const begun = await mixed.begin();
			const refused = await mixed.callback(`code=good&state=${begun.state}`, begun.cookie);
			expect([refused.status, refused.body]).toEqual([400, { error: "invalid_state" }]);
		});
	});

	it("refuses a callback whose round trip goes on to a continuation not composed, clearing its cookie and warning", async () => {
		const kept = memoryRecords<StoredRoundTrip>(() => now, { shards: 1, perShard: 1 });
		const trips = defineModule({ name: "trips" }, (m) => [
			m.provide(roundTripStore).by(() => ({
				save: async (key, value, lifetimeMs) => {
					// Carried as if a continuation of another name had begun it.
					const by = { ...(value as unknown as { carried: object }).carried, by: "elsewhere" };
					const record = { ...(value as object), carried: by } as never;
					return kept.records.create(key, record, lifetimeMs);
				},
				update: kept.records.change,
			})),
		]);
		const s = await serve({ trips });
		const started = await s.begin();
		const back = await s.callback(`code=good&state=${started.state}`, started.cookie);
		expect([back.status, back.body]).toEqual([400, { error: "continuation_unavailable" }]);
		expect(back.cookies).toContain("__Host-federation.corp=");
		expect(logged()).toContain('federation.continuation_missing {"idp":"corp","name":"elsewhere"}');
	});

	it("begins anew on a start from this deployment's own page, or once the browser's round trip has ended or been taken", async () => {
		const s = await serve({ federation: { "transaction-lifetime": "1m" } });
		const fresh = (started: { location: string }) =>
			new URL(started.location).searchParams.get("state");
		const first = await s.begin();
		const own = await s.get(`${base}/corp`, first.cookie, { "sec-fetch-site": "same-origin" });
		expect(fresh(own)).not.toBe(first.state);
		expect(own.cookies.filter((c) => c.includes("federation.corp"))).toHaveLength(1);
		const second = await s.begin();
		await s.callback(`code=good&state=${second.state}`, second.cookie);
		const afterTaken = await s.get(`${base}/corp`, second.cookie, {
			"sec-fetch-site": "cross-site",
		});
		expect(fresh(afterTaken)).not.toBe(second.state);
		const third = await s.begin();
		now += 60_000;
		const afterEnd = await s.get(`${base}/corp`, third.cookie, { "sec-fetch-site": "cross-site" });
		expect(fresh(afterEnd)).not.toBe(third.state);
	});

	it("refuses a start asking a link where none is composed, and warns, writing nothing", async () => {
		const s = await serve({ withoutLink: true });
		const kept = s.saved.length;
		const asked = await s.get(`${base}/corp?link=1`, "", { "sec-fetch-site": "same-origin" });
		expect([asked.status, asked.body]).toEqual([400, { error: "continuation_unavailable" }]);
		expect(asked.cookies.filter((c) => c.includes("federation.corp"))).toEqual([]);
		expect(s.saved.length).toBe(kept);
		expect(logged()).toContain('federation.continuation_missing {"idp":"corp","name":"link"}');
		// A login is no continuation: it starts as ever.
		expect((await s.begin()).status).toBe(302);
	});

	it("checks a link start's origin before it makes any transaction, so another site starts none", async () => {
		const s = await serve();
		const first = await s.begin();
		const loggedIn = await s.callback(
			`code=good&state=${first.state}&iss=https://idp.example`,
			first.cookie,
		);
		const session = loggedIn.cookies.filter((c) => !c.includes("federation.corp=")).join("; ");
		const kept = s.saved.length;
		const refused = await s.get(`${base}/corp?link=1`, session, { "sec-fetch-site": "cross-site" });
		expect([refused.status, refused.body]).toEqual([
			403,
			{ error: "link_requires_trusted_origin" },
		]);
		expect(s.saved.length).toBe(kept);
		expect(refused.cookies.filter((c) => c.includes("federation.corp"))).toEqual([]);
	});

	it("ends a link's round trip in the link, never in a login", async () => {
		const s = await serve();
		const first = await s.begin();
		const loggedIn = await s.callback(
			`code=good&state=${first.state}&iss=https://idp.example`,
			first.cookie,
		);
		const session = loggedIn.cookies.filter((c) => !c.includes("federation.corp=")).join("; ");
		const started = await s.get(`${base}/corp?link=1`, session, {
			"sec-fetch-site": "same-origin",
		});
		expect(started.status).toBe(302);
		const state = new URL(started.location).searchParams.get("state") ?? "";
		const cookie = started.cookies.find((c) => c.includes("federation.corp")) ?? "";
		const before = s.events.length;
		const back = await s.callback(
			`code=good&state=${state}&iss=https://idp.example`,
			`${session}; ${cookie}`,
		);
		expect([back.status, back.location]).toEqual([302, `${origin}/`]);
		expect(back.cookies.filter((c) => !c.includes("federation.corp="))).toEqual([]);
		expect(s.events.slice(before).filter((e) => e.kind.startsWith("federation.login."))).toEqual(
			[],
		);
	});

	it("starts a link, with nothing judging entry, only from a sign-in at a known time within 300 s", async () => {
		const s = await serve({
			answers: answering(["unsaid", { subject: "u-alice", amr: [] }], ["now", aliceAt(now)]),
		});
		/** The session a federation login opens, its cookies as a browser sends them. */
		const sessionOf = async (code: string) => {
			const back = await s.roundTrip(`code=${code}&iss=https://idp.example`);
			return back.cookies.filter((c) => !c.includes("federation.corp=")).join("; ");
		};
		const linkFrom = async (session: string) => {
			const started = await s.get(`${base}/corp?link=1`, session, {
				"sec-fetch-site": "same-origin",
			});
			return [started.status, started.body];
		};
		const unknown = await sessionOf("unsaid");
		const recent = await sessionOf("now");
		const stepUp = [403, { error: "step_up_required", requirement: "session" }];
		expect(await linkFrom(unknown)).toEqual(stepUp);
		expect((await linkFrom(recent))[0]).toBe(302);
		now += 301_000;
		expect(await linkFrom(recent)).toEqual(stepUp);
	});

	it("refuses to boot without csrf, whose origin evidence a start needs, as a link does", async () => {
		const refusedAt = (setup: Setup) =>
			serve(setup).then(
				() => [],
				(error: BootRefused) =>
					error.refusals.filter((r) => r.reason.includes("csrf")).map((r) => r.where),
			);
		expect(await refusedAt({ withoutCsrf: true, withoutLink: true })).toEqual(["federation"]);
		expect(await refusedAt({ withoutCsrf: true })).toContain("federation-link");
	});

	it("sends the browser upstream with PKCE, a state and a nonce, and logs it in on its way back", async () => {
		const s = await serve();
		const started = await s.begin("?prompt=login&max_age=60");
		expect(started.status).toBe(302);
		expect(started.location.startsWith("https://idp.example/authorize?")).toBe(true);
		const [asked] = s.asked.starts;
		expect(asked).toMatchObject({
			challengeMethod: "S256",
			redirectUri: `${origin}${base}/corp/callback`,
			prompt: "login",
			maxAgeSeconds: 60,
			state: started.state,
		});
		const back = await s.callback(
			`code=good&state=${started.state}&iss=https://idp.example`,
			started.cookie,
		);
		expect([back.status, back.location]).toEqual([302, `${origin}/`]);
		const [exchange] = s.asked.exchanges;
		expect(exchange?.iss).toBe("https://idp.example");
		expect(
			createHash("sha256")
				.update(exchange?.verifier ?? "")
				.digest("base64url"),
		).toBe(asked?.challenge);
		expect(exchange?.nonce).toBe(asked?.nonce);
		expect(await s.amrOf(back.cookies)).toEqual(["fed"]);
	});

	it("lands where the operator says when the login named no target", async () => {
		const s = await serve({ federation: { landing: "https://app.example/home" } });
		const back = await s.roundTrip("code=good");
		expect(back.location).toBe("https://app.example/home");
	});

	it("lands only on an https URL kept as written: no userinfo, no fragment", () => {
		const landing = (value: string) => section.safeParse({ landing: value }).success;
		expect(landing("https://app.example/home?x=1")).toBe(true);
		for (const value of [
			"http://app.example/",
			"https://u@app.example/",
			"https://app.example/#/home",
		]) {
			expect(landing(value), value).toBe(false);
		}
	});

	it("types what a type's open receives by the settings schema it contributes", async () => {
		const type = idpType({
			type: "typed",
			settings: z.strictObject({ issuer: z.string(), port: z.number().default(443) }),
			open: async (read) => {
				expectTypeOf(read).toEqualTypeOf<{ issuer: string; port: number }>();
				// @ts-expect-error: nothing the schema does not read
				void read.other;
				throw new Error(`${read.issuer}:${read.port}`);
			},
		});
		const at = { idp: "a", redirectUri: "https://as.example/cb" };
		await expect(type.open({ issuer: "i", port: 1 }, at)).rejects.toThrow("i:1");
	});

	it("returns only to a target a login may return to", async () => {
		const s = await serve({ extra: [returnTo("/oauth/authorize")] });
		expect((await s.begin("?redirect_to=https://evil.example/")).status).toBe(400);
		const target = `${origin}/oauth/authorize?client_id=app`;
		const back = await s.roundTrip("code=good", `?redirect_to=${encodeURIComponent(target)}`);
		expect([back.status, back.location]).toEqual([302, target]);
	});

	it("takes a transaction only with its own state, once, so a request from elsewhere cannot spend it", async () => {
		const s = await serve();
		const started = await s.begin();
		const wrong = await s.callback("code=good&state=wrong", started.cookie);
		expect(wrong.body).toEqual({ error: "invalid_state" });
		// Same length in bytes, other bytes: refused as a wrong state too.
		const last = started.state.endsWith("A") ? "B" : "A";
		const other = await s.callback(
			`code=good&state=${started.state.slice(0, -1)}${last}`,
			started.cookie,
		);
		expect(other.body).toEqual({ error: "invalid_state" });
		// Same length in characters, longer in bytes: still refused as a wrong state, never a failure.
		const wide = `${started.state.slice(0, -1)}${encodeURIComponent("é")}`;
		const widened = await s.callback(`code=good&state=${wide}`, started.cookie);
		expect(widened.status).toBe(400);
		expect(widened.body).toEqual({ error: "invalid_state" });
		// The browser keeps its transaction's cookie, so the login it is in can still finish.
		expect(wrong.cookies).toEqual([]);
		expect((await s.callback(`code=good&state=${started.state}`, "")).status).toBe(400);
		const back = await s.callback(`code=good&state=${started.state}`, started.cookie);
		expect(back.status).toBe(302);
		// Once taken, the transaction's cookie is cleared with the answer.
		expect(back.cookies).toContain(clearedOf(started.cookie));
		expect((await s.callback(`code=good&state=${started.state}`, started.cookie)).status).toBe(400);
		expect(s.asked.exchanges).toHaveLength(1);
	});

	it("never takes one IdP's transaction at another's callback", async () => {
		const s = await serve({
			federation: {
				idps: {
					corp: { type: "test", issuer: "https://idp.example" },
					other: { type: "test", issuer: "https://other.example" },
				},
			},
		});
		const started = await s.begin();
		const elsewhere = await s.get(
			`${base}/other/callback?code=good&state=${started.state}`,
			started.cookie.replace("federation.corp", "federation.other"),
		);
		expect(elsewhere.status).toBe(400);
		expect((await s.callback(`code=good&state=${started.state}`, started.cookie)).status).toBe(302);
	});

	it("takes no transaction from its cookie sent twice, and leaves it for the browser's own callback", async () => {
		const s = await serve();
		const started = await s.begin();
		const query = `code=good&state=${started.state}`;
		const twice = await s.callback(query, `${started.cookie}; ${started.cookie}`);
		expect([twice.status, twice.body]).toEqual([400, { error: "invalid_state" }]);
		expect((await s.callback(query, started.cookie)).status).toBe(302);
	});

	it("ends a transaction at its lifetime", async () => {
		const s = await serve({ federation: { "transaction-lifetime": "1m" } });
		const started = await s.begin();
		now += 60_000;
		expect((await s.callback(`code=good&state=${started.state}`, started.cookie)).status).toBe(400);
	});

	it("answers an upstream that refuses, fails, cannot be reached, or names no linked user with its error, clearing the transaction's cookie and logging no upstream subject", async () => {
		const s = await serve({
			answers: answering(
				["good", alice],
				["down", "unreachable"],
				["broken", "broken"],
				["copied", "copied"],
				["stranger", { subject: "u-nobody", amr: [] }],
			),
		});
		for (const [answer, status, error] of [
			["error=access_denied", 400, "upstream_refused"],
			["error=access_denied&code=good", 400, "upstream_refused"],
			["x=1", 400, "upstream_refused"],
			["code=bad", 502, "exchange_failed"],
			["code=broken", 502, "exchange_failed"],
			["code=copied", 502, "exchange_failed"],
			["code=down", 503, "temporarily_unavailable"],
			["code=stranger", 401, "unknown_user"],
		] as const) {
			const res = await s.roundTrip(answer);
			expect(res.cookies, answer).toContain(clearedOf(res.started.cookie));
			expect([res.status, res.body], answer).toEqual([status, { error }]);
		}
		expect(logged().join("\n")).not.toContain("u-nobody");
		// A failed exchange is logged by its kind only.
		expect(logged().filter((line) => line.startsWith("federation.exchange_failed"))).toEqual([
			'federation.exchange_failed {"idp":"corp","kind":"refused"}',
			'federation.exchange_failed {"idp":"corp","kind":"failed"}',
			// Refused by another copy of upstreams in the bundle: still a refusal.
			'federation.exchange_failed {"idp":"corp","kind":"refused"}',
		]);
	});

	it("records a login with its subject, IdP and source, and one that failed with its reason", async () => {
		const s = await serve({
			answers: answering(
				["good", alice],
				["down", "unreachable"],
				["stranger", { subject: "u-nobody", amr: [] }],
				["now", { ...alice, authenticatedAt: now }],
			),
		});
		await s.roundTrip("code=good");
		for (const answer of ["error=access_denied", "code=bad", "code=down", "code=stranger"]) {
			await s.roundTrip(answer);
		}
		await s.roundTrip("code=now", "?max_age=0");
		now += 120_000;
		await s.roundTrip("code=now", "?max_age=0");
		// Nothing for a callback that takes no transaction.
		await s.callback("code=good&state=nope", (await s.begin()).cookie);
		const on = { idp: "corp", source: "198.51.100.1" };
		const failed = (reason: string) => ({
			kind: "federation.login.failed",
			at: expect.any(Number),
			attributes: { ...on, reason },
		});
		expect(s.events).toEqual([
			{
				kind: "federation.login.succeeded",
				at: expect.any(Number),
				subject: "alice",
				attributes: on,
			},
			failed("upstream_refused"),
			failed("exchange_failed"),
			failed("unknown_user"),
			{
				kind: "federation.login.succeeded",
				at: expect.any(Number),
				subject: "alice",
				attributes: on,
			},
			failed("login_required"),
		]);
		expect(JSON.stringify(s.events)).not.toMatch(/u-alice|u-nobody/);
	});

	it("logs in a browser that asked to log in again only with an upstream login made after it asked", async () => {
		const s = await serve({
			answers: answering(
				["none", { subject: "u-alice", amr: [] }],
				["before", aliceAt(now - 1000 - skewMs)],
				["skewed", aliceAt(now - 1000)],
				["edge", aliceAt(now - skewMs)],
				["after", aliceAt(now + 1000)],
			),
		});
		const prompted = async (code: string) =>
			(await s.roundTrip(`code=${code}`, "?prompt=login")).status;
		expect(await prompted("none")).toBe(401);
		expect(await prompted("before")).toBe(401);
		// The upstream's clock may be behind ours by the allowance its type gives.
		expect(await prompted("skewed")).toBe(302);
		expect(await prompted("edge")).toBe(302);
		expect(await prompted("after")).toBe(302);
		// Any other prompt asks nothing of the upstream login.
		expect((await s.roundTrip("code=before", "?prompt=consent")).status).toBe(302);
		expect(s.asked.starts.at(-1)?.prompt).toBeUndefined();
	});

	it("compares an upstream login time in whole seconds with the start, as upstreams give it", async () => {
		now = Math.floor(now / 1000) * 1000 + 500;
		const s = await serve({
			federation: { idps: { corp: { type: "test", issuer: "https://idp.example", "skew-ms": 0 } } },
			answers: answering(
				// Logged in 300 ms after the start, said in whole seconds.
				["same-second", aliceAt(Math.floor(now / 1000) * 1000)],
				["second-before", aliceAt(Math.floor(now / 1000) * 1000 - 1000)],
			),
		});
		const prompted = async (code: string) =>
			(await s.roundTrip(`code=${code}`, "?prompt=login")).status;
		expect(await prompted("same-second")).toBe(302);
		expect(await prompted("second-before")).toBe(401);
	});

	it("logs in a browser that set a max age only with an upstream login within it and the allowance, even one before the start, and needs the login time only under a max age or prompt=login", async () => {
		const s = await serve({
			answers: answering(
				["none", { subject: "u-alice", amr: [] }],
				["old", aliceAt(now - 60_000 - skewMs - 1)],
				["recent", aliceAt(now - 60_000 - skewMs)],
			),
		});
		const aged = async (code: string, maxAge: number) => {
			const res = await s.roundTrip(`code=${code}`, `?max_age=${maxAge}`);
			return [res.status, res.body] as const;
		};
		expect(await aged("none", 0)).toEqual([401, { error: "login_required" }]);
		expect(await aged("old", 60)).toEqual([401, { error: "login_required" }]);
		expect((await aged("recent", 60))[0]).toBe(302);
		// Asked to log in again, an upstream that never says when the user did cannot satisfy it.
		const again = await s.roundTrip("code=none", "?prompt=login");
		expect([again.status, again.body]).toEqual([401, { error: "login_required" }]);
		// Without prompt or max age, the upstream need not say when it logged in.
		expect((await s.roundTrip("code=none")).status).toBe(302);
	});

	describe("a fresh login's allowance, set for each IdP apart from its clock allowance", () => {
		const corp = (more: object) => ({
			corp: { type: "test", issuer: "https://idp.example", ...more },
		});

		it("narrows what prompt=login and a max age allow to the one set, the type's clock allowance kept", async () => {
			const s = await serve({
				federation: { idps: corp({ "fresh-login-allowance": "5s" }) },
				answers: answering(
					["within", aliceAt(now - 5000)],
					["beyond", aliceAt(now - 6000)],
					["aged", aliceAt(now - 65_000)],
					["older", aliceAt(now - 65_001)],
				),
			});
			const status = async (code: string, query: string) =>
				(await s.roundTrip(`code=${code}`, query)).status;
			// Both lie within the type's 30 s: only the allowance set tells them apart.
			expect(await status("within", "?prompt=login")).toBe(302);
			expect(await status("beyond", "?prompt=login")).toBe(401);
			// A max age is compared in milliseconds, the allowance added.
			expect(await status("aged", "?max_age=60")).toBe(302);
			expect(await status("older", "?max_age=60")).toBe(401);
		});

		it("with 0s, takes no login before the start's second, and still one in it, its time the start's", async () => {
			now = start + 500;
			const s = await serve({
				federation: { idps: corp({ "fresh-login-allowance": "0s" }) },
				answers: answering(
					["same-second", aliceAt(start)],
					["second-before", aliceAt(start - 1000)],
					["ahead", aliceAt(now + 10_000)],
					["unsaid", { subject: "u-alice", amr: [] }],
				),
			});
			const back = await s.roundTrip("code=same-second", "?prompt=login");
			expect(back.status).toBe(302);
			expect((await s.contextOf(back.cookies))?.authenticatedAt).toBe(now);
			expect((await s.roundTrip("code=second-before", "?prompt=login")).status).toBe(401);
			// A time ahead of ours, which the type's clock allowance passes, is taken as the upstream says.
			expect((await s.roundTrip("code=ahead", "?prompt=login")).status).toBe(302);
			expect((await s.roundTrip("code=unsaid", "?prompt=login")).status).toBe(401);
		});

		it("keeps each IdP's allowance apart, each by default its type's clock allowance", async () => {
			const s = await serve({
				federation: {
					idps: {
						...corp({}),
						other: { type: "test", issuer: "https://idp.example", "fresh-login-allowance": "0s" },
					},
				},
				answers: answering(["earlier", aliceAt(now - 10_000)]),
			});
			const at = async (idp: string) => {
				const started = await s.get(`${base}/${idp}?prompt=login`);
				const state = new URL(started.location).searchParams.get("state") ?? "";
				const cookie = started.cookies.find((c) => c.includes(`federation.${idp}`)) ?? "";
				const back = await s.get(`${base}/${idp}/callback?code=earlier&state=${state}`, cookie);
				return [back.status, back.body];
			};
			// The user is linked through corp alone: other's refusal is its allowance's, before the user is looked up.
			expect((await at("corp"))[0]).toBe(302);
			expect(await at("other")).toEqual([401, { error: "login_required" }]);
		});

		it("is taken from 0s to 5m, written with its unit, and never handed to the type", async () => {
			const refusals = (allowance: unknown) =>
				serve({ federation: { idps: corp({ "fresh-login-allowance": allowance }) } }).then(
					() => [],
					(error: BootRefused) => error.refusals.map((r) => r.where),
				);
			// The test type's settings are strict: a key handed on would be refused there.
			expect(await refusals("5m")).toEqual([]);
			expect(await refusals("301s")).toEqual(["federation.idps.corp.fresh-login-allowance"]);
			expect(await refusals(5)).toEqual(["federation.idps.corp.fresh-login-allowance"]);
		});
	});

	it("lets a login return to an IdP's start, and to nothing else under federation's path", async () => {
		const s = await serve();
		const gates = await s.declared(logins);
		expect(gates.returnAllowed(`${origin}${base}/corp?link=1`)).toBe(true);
		expect(gates.returnAllowed(`${origin}${base}/corp`)).toBe(true);
		for (const other of [
			`${origin}${base}?link=1`,
			`${origin}${base}/corp/callback?code=x`,
			`${origin}${base}/corp%2Fcallback`,
			`https://other.example${base}/corp?link=1`,
		]) {
			expect(gates.returnAllowed(other), other).toBe(false);
		}
	});

	it("adds an upstream's amr only as the operator maps it, and declares what it maps to", async () => {
		const s = await serve({
			federation: {
				idps: {
					corp: {
						type: "test",
						issuer: "https://idp.example",
						"upstream-amr": { mfa: "otp", hwk: "hwk" },
					},
				},
			},
			answers: answering(["good", { ...alice, amr: ["mfa", "pwd", "constructor"] }]),
		});
		const back = await s.roundTrip("code=good");
		// Unmapped values are dropped, never passed on as the upstream spelled them.
		expect(await s.amrOf(back.cookies)).toEqual(["fed", "otp"]);
		expect(await s.achievable(["fed", "otp", "hwk"])).toBe(true);
		expect(await s.achievable(["mfa"])).toBe(false);
	});

	it("gives the session the upstream's profile under the IdP's name, its email verified only where the type says so", async () => {
		const said = {
			email: "alice@corp.example",
			name: "Alice",
			picture: "https://pictures.example/alice",
		};
		const profiled = (profile: unknown) => ({ ...alice, profile }) as UpstreamLogin;
		const s = await serve({
			answers: answering(
				["verified", profiled({ ...said, emailVerified: true, groups: ["admin"], role: "admin" })],
				["unverified", profiled({ ...said, emailVerified: "true" })],
				["unsaid", profiled({ email: said.email })],
				["no-email", profiled({ name: 7, emailVerified: true, picture: said.picture })],
				["none", alice],
			),
		});
		const attributesOf = async (code: string) => {
			const back = await s.roundTrip(`code=${code}`);
			expect(back.status).toBe(302);
			return (await s.contextOf(back.cookies))?.attributes;
		};
		const source = loginSource.upstream("corp");
		// Groups and any other claim an upstream sends never reach the session.
		expect(await attributesOf("verified")).toEqual({
			source,
			values: { ...said, email_verified: true },
		});
		expect(await attributesOf("unverified")).toEqual({
			source,
			values: { ...said, email_verified: false },
		});
		expect(await attributesOf("unsaid")).toEqual({
			source,
			values: { email: said.email, email_verified: false },
		});
		expect(await attributesOf("no-email")).toEqual({
			source,
			values: { picture: said.picture },
		});
		expect(await attributesOf("none")).toBeUndefined();
	});

	it("answers a login a gate holds with the gate's answer, opening no session", async () => {
		const gate = defineModule({ name: "gate" }, (m) => [
			m.contribute(loginGates).by(() => ({
				name: "second",
				hold: async () => ({
					kind: "held" as const,
					answer: { step: "next" },
					cookies: ["step=1; Path=/"],
				}),
			})),
		]);
		const s = await serve({ extra: [gate] });
		const held = await s.roundTrip("code=good");
		expect([held.status, held.body]).toEqual([403, { step: "next" }]);
		expect(held.cookies).toContain("step=1");
		expect(s.events).toEqual([
			{
				kind: "federation.login.held",
				at: now,
				subject: "alice",
				attributes: { idp: "corp", source: "198.51.100.1" },
			},
		]);
	});

	it("sends a browser whose login a gate holds to the held page, by 303 with no query, and its cookies", async () => {
		const gate = defineModule({ name: "gate" }, (m) => [
			m.contribute(loginGates).by(() => ({
				name: "second",
				hold: async () => ({
					kind: "held" as const,
					answer: { step: "next" },
					cookies: ["step=1; Path=/"],
				}),
			})),
		]);
		const page = `${origin}/continue`;
		for (const mode of [undefined, "form_post"] as const) {
			const corp = { type: "test", issuer: "https://idp.example", ...(mode ? { mode } : {}) };
			const s = await serve({
				extra: [gate],
				federation: { "held-page": page, idps: { corp } },
			});
			const started = await s.begin();
			const query = `code=good&state=${started.state}`;
			const held = mode
				? await s.post(`${base}/corp/callback`, query, started.cookie)
				: await s.callback(query, started.cookie);
			expect([held.status, held.location], mode).toEqual([303, page]);
			expect(held.cookies, mode).toContain("step=1");
			expect(held.cookies, mode).toContain(clearedOf(started.cookie));
			await stop();
		}
	});

	it("carries where a held login lands, as asked, else the landing, else the public origin's root", async () => {
		const target = `${origin}/oauth/authorize?client_id=app`;
		for (const [federation, query, lands] of [
			[{}, `?redirect_to=${encodeURIComponent(target)}`, target],
			[{ landing: "https://app.example/home" }, "", "https://app.example/home"],
			[{}, "", `${origin}/`],
		] as const) {
			const gate = holdingGate();
			const s = await serve({ extra: [gate.module, returnTo("/oauth/authorize")], federation });
			await s.roundTrip("code=good", query);
			expect(gate.held.map((h) => h.done)).toEqual([{ redirect_to: lands }]);
			await stop();
		}
	});

	it("refuses to boot on a held page off the public origin, naming its key", async () => {
		await expect(
			serve({ federation: { "held-page": "https://app.example/continue" } }),
		).rejects.toSatisfy(
			(error: unknown) =>
				error instanceof BootRefused &&
				error.refusals.some((r) => r.where === "federation.held-page"),
		);
	});

	it("takes an answer in form_post only by POST, behind a cross-site cookie, and one in a query only by GET", async () => {
		const s = await serve({
			federation: {
				idps: {
					corp: { type: "test", issuer: "https://idp.example", mode: "form_post" },
					plain: { type: "test", issuer: "https://idp.example" },
				},
			},
		});
		const { state, cookie } = await s.begin();
		// The test's sender answers a cookie without its attributes, so another start is read raw.
		const raw = await fetch(`${s.at}${base}/corp`, { redirect: "manual", headers: viaProxy });
		expect(raw.headers.getSetCookie().join()).toMatch(
			/^__Host-federation\.corp=[^;]+; Path=\/; HttpOnly; SameSite=None; Secure/,
		);
		expect((await s.get(`${base}/corp/callback?code=good&state=${state}`, cookie)).status).toBe(
			405,
		);
		// A request carrying no answer spends nothing, and keeps the cookie.
		const empty = await s.post(`${base}/corp/callback`, "", cookie);
		expect([empty.status, empty.cookies]).toEqual([400, []]);
		expect((await s.post(`${base}/corp/callback`, "state=x&state=y", cookie)).body).toEqual({
			error: "repeated_parameter",
		});
		const back = await s.post(`${base}/corp/callback`, `code=good&state=${state}`, cookie);
		expect(back.status).toBe(302);
		expect((await s.post(`${base}/plain/callback`, "code=good&state=x")).status).toBe(405);
		expect((await s.post(`${base}/corp`, "")).status).toBe(405);
	});

	it("answers 404 off its IdPs' two paths, and 400 to a repeated parameter or a max age not of 1 to 9 digits", async () => {
		const s = await serve();
		for (const path of [`${base}/other`, `${base}/corp/x`, `${base}/corp/callback/x`, `${base}/`]) {
			expect((await s.get(path)).status, path).toBe(404);
		}
		expect((await s.get(`${base}/corp?prompt=login&prompt=none`)).status).toBe(400);
		for (const maxAge of ["-1", "", "1e3", "1234567890"]) {
			expect((await s.get(`${base}/corp?max_age=${maxAge}`)).status, maxAge).toBe(400);
		}
		expect((await s.get(`${base}/corp?max_age=123456789`)).status).toBe(302);
	});

	it("answers a round trip carrying what it does not know as invalid_state, spent and its cookie cleared", async () => {
		const kept = memoryRecords<StoredRoundTrip>(() => now, { shards: 1, perShard: 1 });
		const odd = defineModule({ name: "trips" }, (m) => [
			m.provide(roundTripStore).by(() => ({
				save: (key, value, lifetimeMs) =>
					kept.records.create(
						key,
						{ ...(value as object), carried: { unheard: 1 } } as unknown as StoredRoundTrip,
						lifetimeMs,
					),
				update: kept.records.change,
			})),
		]);
		const s = await serve({ trips: odd });
		const started = await s.begin();
		const back = await s.callback(`code=good&state=${started.state}`, started.cookie);
		expect([back.status, back.body]).toEqual([400, { error: "invalid_state" }]);
		expect(back.cookies).toContain(clearedOf(started.cookie));
		const again = await s.callback(`code=good&state=${started.state}`, started.cookie);
		expect([again.status, again.cookies]).toEqual([400, []]);
	});

	it("is unavailable when it cannot keep a round trip", async () => {
		const alwaysExists = defineModule({ name: "trips" }, (m) => [
			m.provide(roundTripStore).by(() => ({
				save: async () => "exists" as const,
				update: async () => undefined,
			})),
		]);
		const s = await serve({ trips: alwaysExists });
		const res = await s.begin();
		expect([res.status, res.body]).toEqual([503, { error: "temporarily_unavailable" }]);
	});

	it("gives what an IdP's upstream offers besides a login, by the IdP's name only", async () => {
		const bearer = { accessToken: "a", tokenType: "Bearer", scope: [] };
		const exchanged = {
			code: "c",
			verifier: "v",
			redirectUri: "r",
			nonce: "n",
			iss: undefined,
			scopes: ["openid"],
		};
		const refresh = async () => ({ kind: "invalid_grant" as const });
		const endSession = () => "https://idp.example/logout";
		const delegation: Delegation = {
			authorizationUrl: (start) => `https://idp.example/offline?scope=${start.scopes.join("+")}`,
			exchange: async () => ({ ...alice, issuer: "https://idp.example", tokens: bearer }),
			refresh,
		};
		const s = await serve({ more: { refresh, endSession, delegation } });
		const of = (await s.upstreams()).of;
		expect(of("corp")?.refresh).toBe(refresh);
		expect(of("corp")?.endSession?.({ state: "s" })).toBe("https://idp.example/logout");
		expect(await of("corp")?.delegation?.exchange(exchanged)).toMatchObject({ tokens: bearer });
		// Only what it offers: never the login's authorization URL or code exchange.
		expect(Object.keys(of("corp") ?? {}).sort()).toEqual(["delegation", "endSession", "refresh"]);
		const plain = await (await serve()).upstreams();
		expect(Object.keys(plain.of("corp") ?? {})).toEqual([]);
		for (const name of ["other", "constructor", "__proto__", "Corp"]) {
			expect(of(name), name).toBeUndefined();
		}
	});

	it("declares its start and its callback apart, each with its own reason and its rate limit, and each reaches its own", async () => {
		const declared = contract<readonly Route[]>("test.declared");
		const reached: string[] = [];
		const probe = defineModule({ name: "probe" }, (m) => [
			m.provide(declared).by((c) => c.collect(routes)),
			m.contribute(requestEnds).by(() => ({ ended: (end) => void reached.push(end.route ?? "") })),
		]);
		const s = await serve({ extra: [probe] });
		const ours = s.declared(declared).filter((r) => r.path.startsWith(`${base}/`));
		expect(ours.map((r) => `${r.method} ${r.path}`).sort()).toEqual([
			`GET ${base}/*`,
			`GET ${base}/*/callback`,
			`POST ${base}/*/callback`,
		]);
		const reasonOf = (path: string) =>
			new Set(ours.filter((r) => r.path === path).map((r) => r.crossSite));
		expect([...reasonOf(`${base}/*`)]).toEqual([
			expect.stringMatching(/^A start is the user's own navigation/),
		]);
		expect([...reasonOf(`${base}/*/callback`)]).toEqual([
			expect.stringMatching(/^A callback is the IdP's redirect or form_post/),
		]);
		for (const route of ours) {
			// A GET says it changes state; any other method does.
			if (route.method === "GET") expect(route.changesState, route.path).toBe(true);
			expect(route.uses?.length, route.path).toBe(1);
		}
		const started = await s.begin();
		await s.callback(`code=good&state=${started.state}`, started.cookie);
		await s.post(`${base}/corp/callback`, "code=good");
		await expect.poll(() => reached.length).toBe(3);
		expect(reached).toEqual([`${base}/*`, `${base}/*/callback`, `${base}/*/callback`]);
	});

	it("limits starts and callbacks per source", async () => {
		const s = await serve({ federation: { requests: 2 } });
		await s.begin();
		await s.begin();
		expect((await s.begin()).status).toBe(429);
	});

	it("names each IdP to users with its upstream's issuer, so another route naming it for another issuer refuses boot", async () => {
		const naming = (issuer: string) =>
			defineModule({ name: "elsewhere" }, (m) => [
				m.contribute(upstreamNames).by(() => ({
					declaredBy: "elsewhere",
					names: [{ name: "corp", issuer }],
				})),
			]);
		const idps = { corp: { type: "test", issuer: "https://idp.example" } };
		const refused = await serve({ federation: { idps }, extra: [naming("https://other.example")] })
			.then(() => [])
			.catch((error: BootRefused) => error.refusals.map((r) => r.reason));
		// users names the modules that declare the name, never the name or an issuer.
		expect(refused).toEqual([expect.stringContaining("federation")]);
		await expect(
			serve({ federation: { idps }, extra: [naming("https://idp.example")] }),
		).resolves.toBeDefined();
	});

	it("refuses to boot on an unknown type, bad settings, an upstream that does not match, or no public origin", async () => {
		const refused = async (idps: Record<string, unknown>, origin?: string | null) => {
			try {
				await serve({ federation: { idps }, ...(origin === undefined ? {} : { origin }) });
				return [];
			} catch (error) {
				if (!(error instanceof BootRefused)) throw error;
				return error.refusals.map((r) => r.where);
			}
		};
		expect(await refused({ a: { type: "nope" } })).toEqual(["federation.idps.a.type"]);
		expect(await refused({ a: { type: "test", issuer: 1 } })).toEqual(["federation.idps.a.issuer"]);
		expect(await refused({ a: { type: "test", issuer: "https://mismatch.example" } })).toEqual([
			"federation.idps.a",
		]);
		// The type's own reason, under the key it names in the IdP's settings.
		const told = await serve({
			federation: { idps: { a: { type: "test", issuer: "https://misdescribed.example" } } },
		}).catch((error: BootRefused) => error.refusals);
		expect(told).toEqual([
			{ where: "federation.idps.a.issuer", reason: "the description names another issuer" },
		]);
		// Thrown by another copy of upstreams in the bundle: still the type's own reason, under its key.
		const copied = await serve({
			federation: { idps: { a: { type: "test", issuer: "https://copied.example" } } },
		}).catch((error: BootRefused) => error.refusals);
		expect(copied).toEqual([
			{ where: "federation.idps.a.issuer", reason: "the description names another issuer" },
		]);
		// A type's own settings are read as a section is: a string from the environment converts.
		const typed = { type: "test", issuer: "https://idp.example", "skew-ms": "0", refuses: "false" };
		expect(await refused({ corp: typed })).toEqual([]);
		const converted = await serve({
			federation: { idps: { corp: { ...typed, refuses: "true" } } },
		}).catch((error: BootRefused) => error.refusals);
		expect(converted).toEqual([
			{ where: "federation.idps.corp.refuses", reason: "refused by its settings" },
		]);
		expect(await refused({ corp: { ...typed, "skew-ms": "soon" } })).toEqual([
			"federation.idps.corp.skew-ms",
		]);
		// An upstream that cannot be reached is told apart from one that does not match.
		const reasons = async (issuer: string) =>
			serve({ federation: { idps: { a: { type: "test", issuer } } } }).catch(
				(error: BootRefused) => error.refusals,
			);
		expect(await reasons("https://mismatch.example")).toEqual([
			{ where: "federation.idps.a", reason: "the upstream does not match its settings" },
		]);
		expect(await reasons("https://unreachable.example")).toEqual([
			{ where: "federation.idps.a", reason: "the upstream could not be reached" },
		]);
		expect(
			await refused({ "Bad.Name": { type: "test", issuer: "https://idp.example" } }),
		).not.toEqual([]);
		// An amr of ours is one token; an upstream's maps only to such a value.
		expect(
			await refused({
				a: { type: "test", issuer: "https://idp.example", "upstream-amr": { mfa: "two words" } },
			}),
		).not.toEqual([]);
		expect(await refused({ a: { type: "test", issuer: "https://idp.example" } }, null)).toEqual([
			"federation.idps.a",
		]);
		expect(
			await refused(
				{ a: { type: "test", issuer: "https://idp.example", mode: "form_post" } },
				"http://as.example",
			),
		).toEqual(["federation.idps.a"]);
	});
});

describe("a deployment with no IdP", () => {
	it("warns at every boot that composes none, as every login then answers not found", async () => {
		await serve({ federation: { idps: {} }, unlinked: true });
		expect(logged()).toContain("federation.no_idps {}");
		await stop();
		logStart = recorded.lines().length;
		await serve();
		expect(logged().filter((line) => line.startsWith("federation.no_idps"))).toEqual([]);
	});
});

const returnTo = (path: string) =>
	defineModule({ name: `return-${path}` }, (m) => [m.contribute(returnPaths).by(() => ({ path }))]);

interface Held {
	readonly facts: LoginFacts;
	readonly done: unknown;
	readonly from?: LoginFrom;
}

/** A stand-in gate that holds every login, keeping what login-gates hands it, as a gate that resumes it would. */
function holdingGate() {
	const held: Held[] = [];
	const module = defineModule({ name: "holding-gate" }, (m) => [
		m.contribute(loginGates).by(() => ({
			name: "second",
			hold: async (_request, facts, done, from) => {
				held.push({ facts, done, ...(from === undefined ? {} : { from }) });
				return { kind: "held" as const, answer: { step: "next" } };
			},
		})),
	]);
	return { module, held };
}

interface Told {
	readonly receiver: string;
	readonly session: Session;
	readonly idp: string;
	readonly tokens: UpstreamTokens;
}

/** Receivers for tests, telling one list what each was given; those named in `failing` throw. */
function receivers(names: readonly string[], failing: readonly string[] = []) {
	const told: Told[] = [];
	const modules = names.map((name) =>
		defineModule({ name: `receiver-${name}` }, (m) => [
			m.contribute(upstreamLoginReceivers).by(() => ({
				name,
				received: async (at) => {
					told.push({ receiver: name, ...at });
					if (failing.includes(name)) throw new RangeError("receiver down");
				},
				withdrawn: async () => {},
			})),
		]),
	);
	return { modules, told };
}

describe("upstream tokens", () => {
	const tokens: UpstreamTokens = {
		accessToken: "at-secret",
		tokenType: "Bearer",
		refreshToken: "rt-secret",
		idToken: "id-secret",
		expiresInSeconds: 3600,
		scope: ["openid", "email"],
	};
	const answers = answering(["tokens", { ...alice, tokens }], ["bare", alice]);

	it("hands them to every receiver, by name, when the login opens without a hold, keeping nothing", async () => {
		const told = receivers(["b", "a"]);
		const s = await serve({ answers, receivers: told.modules });
		const back = await s.roundTrip("code=tokens");
		expect(back.status).toBe(302);
		expect(told.told.map((t) => [t.receiver, t.idp, t.session.context.subject])).toEqual([
			["a", "corp", "alice"],
			["b", "corp", "alice"],
		]);
		expect(told.told[0]?.tokens).toEqual(tokens);
		expect(s.saved).toHaveLength(1);
	});

	it("keeps them sealed while a gate holds the login, and hands them over once, when it opens", async () => {
		const gate = holdingGate();
		const told = receivers(["a"]);
		const s = await serve({ answers, extra: [gate.module], receivers: told.modules });
		const held = await s.roundTrip("code=tokens");
		expect([held.status, told.told]).toEqual([403, []]);
		const [kept] = gate.held;
		expect(kept?.from?.caller).toBe("federation");
		expect(s.saved).toHaveLength(2);
		expect(s.saved.join()).not.toMatch(/at-secret|rt-secret|id-secret/);
		now += 100_500;
		// Told at once twice, as two hosts could be: still handed over only once.
		const opened = await Promise.all([s.resume(kept as Held), s.resume(kept as Held)]);
		expect(opened.map((o) => o.kind)).toEqual(["opened", "opened"]);
		expect(told.told.map((t) => [t.session.context.subject, t.tokens])).toEqual([
			["alice", { ...tokens, expiresInSeconds: 3600 - 101 }],
		]);
		await s.resume(kept as Held);
		expect(told.told).toHaveLength(1);
	});

	it("hands nothing to a session of another subject", async () => {
		const gate = holdingGate();
		const told = receivers(["a"]);
		const s = await serve({ answers, extra: [gate.module], receivers: told.modules });
		await s.roundTrip("code=tokens");
		const [kept] = gate.held as [Held];
		await s.resume(kept, { ...kept.facts, subject: "bob" });
		await s.resume(kept);
		expect(told.told).toEqual([]);
	});

	it("has login-gates refuse a held login resumed at its deadline, so none opens without its tokens", async () => {
		const gate = holdingGate();
		const told = receivers(["a"]);
		const s = await serve({ answers, extra: [gate.module], receivers: told.modules });
		await s.roundTrip("code=tokens");
		await s.roundTrip("code=tokens");
		const [early, late] = gate.held as [Held, Held];
		expect(late.from?.deadline).toBe(now + 600_000);
		// The carry is only the key of the kept tokens: 256 random bits.
		expect(late.from?.carry).toMatch(/^[\w-]{43}$/);
		now += 599_999;
		expect((await s.resume(early)).kind).toBe("opened");
		now += 1;
		const refused = await s.resume(late);
		expect(refused.kind).toBe("expired");
		expect(told.told).toHaveLength(1);
	});

	it("leaves a login another caller asked for alone", async () => {
		const other = defineModule({ name: "other-caller" }, (m) => [
			m.contribute(openedAfterHold).by(() => ({ caller: "other", opened: async () => {} })),
		]);
		const told = receivers(["a"]);
		const s = await serve({ answers, extra: [other], receivers: told.modules });
		expect((await s.login({ caller: "other", carry: "kept" })).kind).toBe("opened");
	});

	it("keeps the login open when a receiver fails, telling the others and logging it by name and kind", async () => {
		const told = receivers(["a", "b"], ["a"]);
		const s = await serve({ answers, receivers: told.modules });
		expect((await s.roundTrip("code=tokens")).status).toBe(302);
		expect(told.told.map((t) => t.receiver)).toEqual(["a", "b"]);
		expect(logged()).toContain(
			'upstream-handoff.receiver_failed {"receiver":"a","kind":"RangeError"}',
		);
		expect(logged().join()).not.toContain("secret");
	});

	it("asks login-gates to carry nothing without tokens, or with no receiver, and needs no seal then", async () => {
		const gate = holdingGate();
		await (await serve({ answers, extra: [gate.module] })).roundTrip("code=tokens");
		const told = receivers(["a"]);
		const receiving = await serve({ answers, extra: [gate.module], receivers: told.modules });
		await receiving.roundTrip("code=bare");
		expect(gate.held.map((h) => h.from)).toEqual([undefined, undefined]);
	});

	it("is unavailable when it cannot keep the tokens of a held login", async () => {
		const gate = holdingGate();
		const full = defineModule({ name: "held" }, (m) => [
			m.provide(heldLoginStore).by(() => ({
				save: async () => "exists" as const,
				update: async () => undefined,
				remove: async () => {},
			})),
		]);
		const told = receivers(["a"]);
		const s = await serve({ answers, extra: [gate.module], receivers: told.modules, held: full });
		const res = await s.roundTrip("code=tokens");
		expect([res.status, res.body]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(res.cookies).toContain(clearedOf(res.started.cookie));
	});
});
