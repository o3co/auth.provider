import { auditStandIn } from "@mod/audit/testing";
import { clientSources } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, publicClient } from "@mod/clients/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { type Session, sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, describe, expect, it } from "vitest";
import { type Asked, clientSection, consents, isFirstParty } from "../src/contract.ts";
import consentModule from "../src/module.ts";
import { section } from "../src/section.ts";
import type { StoredAsk, StoredGrant } from "../src/store.ts";
import { consentConfig, consentStoresOn, type RecordsStandIn } from "../src/testing.ts";

/** What the tests share: the composition's clock, how far the store's falls behind it, and the running app. */
const start = 1_800_000_000_000;
let now = start;
const behind = { ms: 0 };
let stop = async () => {};
afterEach(async () => {
	now = start;
	behind.ms = 0;
	await stop();
});

const runtime = quietRuntime({ clock: { now: () => now } });
const asked: Asked = {
	clientId: "app",
	range: ["read", "write"],
	onAccept: "https://as.example/oauth/authorize?resume=1",
	onDeny: "https://as.example/oauth/authorize?consent_denied=1",
};

/**
 * Records on the stand-in, on a store clock that can fall behind the composition's. A write can
 * take effect and lose its answer, another writer can come just before one, on its key, and a
 * call can be made unavailable through `down`.
 */
function faulty<T extends StoredGrant | StoredAsk>() {
	const stand = memoryRecords<T>(() => now - behind.ms, { shards: 1, perShard: 1 });
	type Operation = "create" | "change";
	let lose: Operation | undefined;
	let before: { operation: Operation; run: (key: string) => Promise<unknown> } | undefined;
	const keys: string[] = [];
	const down = unavailableSwitch<RecordsStandIn<T>["records"]>("consent records");
	const around =
		<A extends [string, ...unknown[]], R>(operation: Operation, call: (...args: A) => Promise<R>) =>
		async (...args: A) => {
			const first = before?.operation === operation ? before.run : undefined;
			if (first) before = undefined;
			await first?.(args[0]);
			if (operation === "create") keys.push(args[0]);
			const result = await call(...args);
			if (lose !== operation) return result;
			lose = undefined;
			throw new Unavailable("lost answer");
		};
	return {
		stand,
		/** The keys saved, in order. */
		keys,
		down,
		records: down.wrap({
			create: around("create", stand.records.create),
			read: stand.records.read,
			change: around("change", stand.records.change),
		}),
		loseNext: (operation: Operation) => {
			lose = operation;
		},
		beforeNext: (operation: Operation, run: (key: string) => Promise<unknown>) => {
			before = { operation, run };
		},
	};
}

/** A client a source other than the operator's settings shows, as a metadata document would. */
const documentId = "https://docs.example/client.json";
const documents = defineModule({ name: "documents" }, (m) => [
	m.contribute(clientSources).by(() => ({
		find: async (id: string) =>
			id === documentId
				? {
						id,
						kind: "public" as const,
						method: "none",
						sections: { [clientSection.name]: { name: " Docs ", host: "docs.example" } },
					}
				: undefined,
	})),
]);

const challengeOf = (url: string) => new URL(url).searchParams.get("challenge") ?? "";

/** `page` null composes consent without a consent page. */
async function serve(
	origin: string | null = "https://as.example",
	page: string | null = "https://as.example/consent",
) {
	const grants = faulty<StoredGrant>();
	const asks = faulty<StoredAsk>();
	const recorded = auditStandIn();
	const app = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			documents,
			recorded.module,
			csrfStandIn,
			cookiesModule,
			sessionStandIn,
			subjectRevocationStandIn,
			consentStoresOn({ grants, asks }),
			consentModule,
		],
		config: {
			...kernelConfig(),
			...httpConfig({
				"trusted-proxies": ["127.0.0.1"],
				...(origin === null ? {} : { "public-origin": origin }),
			}),
			...clientsConfig([
				publicClient({ id: "app" }),
				publicClient({
					id: "named",
					sections: {
						[clientSection.name]: {
							name: "Acme",
							uri: "https://acme.example/about",
							host: "acme.example",
						},
					},
				}),
			]),
			...(page === null
				? { consent: { "challenge-lifetime": "1m" } }
				: consentConfig({ "challenge-lifetime": "1m", page })),
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	const opened = app.get(sessions);
	const given = app.get(consents);
	const sessionFor = async (subject: string) => {
		const { cookies } = await opened.complete(testRequest(), {
			subject,
			amr: ["pwd"],
			authenticatedAt: runtime.clock.now(),
		});
		const cookie = cookies[0]?.split(";")[0] ?? "";
		const session = (await opened.enter(
			testRequest({ headers: new Map([["cookie", cookie]]) }),
		)) as Session;
		return { cookie, session };
	};
	const call = async (
		method: "GET" | "POST",
		cookie: string,
		params: Record<string, string> | string,
		headers: Record<string, string> = { origin: "https://as.example" },
	) => {
		const query = method === "GET" ? `?${new URLSearchParams(params)}` : "";
		const res = await fetch(`${base}/oauth/consent${query}`, {
			method,
			redirect: "manual",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.1",
				cookie,
				"content-type": "application/x-www-form-urlencoded",
				...headers,
			},
			...(method === "POST"
				? { body: typeof params === "string" ? params : new URLSearchParams(params) }
				: {}),
		});
		const text = await res.text();
		return {
			status: res.status,
			location: res.headers.get("location"),
			cacheControl: res.headers.get("cache-control"),
			body: text ? JSON.parse(text) : undefined,
		};
	};
	/** A session for the subject with a pending consent asked of it, and the calls on that consent. */
	const pendingFor = async (subject: string, request: Asked = asked) => {
		const { cookie, session } = await sessionFor(subject);
		const challenge = challengeOf(await given.ask(session, request));
		return {
			cookie,
			session,
			challenge,
			show: () => call("GET", cookie, { challenge }),
			answer: (decision: string, headers?: Record<string, string>) =>
				call("POST", cookie, { challenge, decision }, headers),
		};
	};
	return { grants, asks, sessionFor, pendingFor, call, given, events: recorded.events };
}

describe("consent: asking", () => {
	it("refuses destinations off the public origin and ranges that are not distinct words", async () => {
		const { sessionFor, given } = await serve();
		const { session } = await sessionFor("alice");
		const refused: Record<string, Asked> = {
			"javascript: destination": { ...asked, onAccept: "javascript:alert(1)" },
			"deny off the origin": { ...asked, onDeny: "https://app.example/cb" },
			"http destination": { ...asked, onAccept: "http://as.example/x" },
			"repeated scope": { ...asked, range: ["read", "read"] },
			"empty scope": { ...asked, range: [""] },
			"scope with a space": { ...asked, range: ["read write"] },
		};
		for (const [name, bad] of Object.entries(refused)) {
			await expect(given.ask(session, bad), name).rejects.toThrow(TypeError);
		}
	});

	it("refuses a range holding a control character", async () => {
		const { sessionFor, given } = await serve();
		const { session } = await sessionFor("alice");
		for (const scope of ["read\x00", "\x1bread", "re\x7fad", "read\u0085"]) {
			await expect(given.ask(session, { ...asked, range: [scope] }), scope).rejects.toThrow(
				TypeError,
			);
		}
	});

	it("refuses a destination holding whitespace or a control character, which the URL parser would drop", async () => {
		const { sessionFor, given } = await serve();
		const { session } = await sessionFor("alice");
		for (const onAccept of [
			"https://as.example/oauth/authorize\r\n?x=1",
			"https://as.example/oauth/authorize\t?x=1",
			" https://as.example/x",
			"\x01https://as.example/x",
			"https://as.exa\nmple/x",
			"https://as.example/x\x7f",
			"https://as.example/x\u0085",
		]) {
			await expect(given.ask(session, { ...asked, onAccept }), onAccept).rejects.toThrow(TypeError);
			await expect(given.ask(session, { ...asked, onDeny: onAccept }), onAccept).rejects.toThrow(
				TypeError,
			);
		}
	});

	it("asks nobody without a consent page, and takes an ask then as the caller's mistake", async () => {
		const { sessionFor, given } = await serve("https://as.example", null);
		expect(given.asking).toBe(false);
		const alice = await sessionFor("alice");
		await expect(given.ask(alice.session, asked)).rejects.toThrow(TypeError);
	});

	it("refuses to start without a public origin to hold destinations to", async () => {
		await expect(serve(null)).rejects.toMatchObject({
			name: "BootRefused",
			refusals: expect.arrayContaining([expect.objectContaining({ where: "consent" })]),
		});
	});

	it("keeps the range as asked, whatever the caller does with its array afterwards", async () => {
		const { sessionFor, call, given } = await serve();
		const alice = await sessionFor("alice");
		const range = ["read"];
		const challenge = challengeOf(await given.ask(alice.session, { ...asked, range }));
		range.push("admin");
		expect((await call("GET", alice.cookie, { challenge })).body.scopes).toEqual(["read"]);
	});
});

describe("consent: the page", () => {
	it("parks a request for the session's subject and shows it only to that session", async () => {
		const { sessionFor, call, given } = await serve();
		const alice = await sessionFor("alice");
		expect(given.asking).toBe(true);
		const page = await given.ask(alice.session, asked);
		expect(page.startsWith("https://as.example/consent?challenge=")).toBe(true);
		const challenge = challengeOf(page);
		const shown = await call("GET", alice.cookie, { challenge });
		expect([shown.status, shown.body]).toEqual([
			200,
			{ client_id: "app", scopes: ["read", "write"], granted_scopes: [], expires_in: 60 },
		]);
		const other = await sessionFor("alice");
		expect((await call("GET", other.cookie, { challenge })).status).toBe(400);
		expect((await call("GET", "", { challenge })).status).toBe(401);
	});

	it("shows the client's name and page, and the verified host only for a client from another source", async () => {
		const { pendingFor } = await serve();
		const shown = async (clientId: string) => {
			const { client_id, client_name, client_uri, client_id_host } = (
				await (await pendingFor("alice", { ...asked, clientId })).show()
			).body;
			return { client_id, client_name, client_uri, client_id_host };
		};
		expect(await shown("named")).toEqual({
			client_id: "named",
			client_name: "Acme",
			client_uri: "https://acme.example/about",
		});
		expect(await shown(documentId)).toEqual({
			client_id: documentId,
			client_name: "Docs",
			client_id_host: "docs.example",
		});
	});

	it("knows no challenge that is missing or not of the shape it hands out", async () => {
		const { pendingFor, call } = await serve();
		const { cookie } = await pendingFor("alice");
		const unknown = [400, { error: "unknown_challenge" }];
		const near = ["A".repeat(42), "A".repeat(44), `${"A".repeat(42)}+`];
		for (const params of [{}, { challenge: "x" }, ...near.map((challenge) => ({ challenge }))]) {
			const shown = await call("GET", cookie, params);
			expect([shown.status, shown.body]).toEqual(unknown);
			const answered = await call("POST", cookie, { ...params, decision: "accept" });
			expect([answered.status, answered.body]).toEqual(unknown);
		}
	});

	it("shows nothing for a client gone since the consent was asked", async () => {
		const { pendingFor } = await serve();
		const shown = await (await pendingFor("alice", { ...asked, clientId: "gone" })).show();
		expect([shown.status, shown.body]).toEqual([400, { error: "unknown_challenge" }]);
	});
});

describe("consent: the answer", () => {
	it("records the grant on acceptance and sends the user on; a resend gets the same answer, the other decision none", async () => {
		const { pendingFor, given } = await serve();
		const alice = await pendingFor("alice");
		const accepted = await alice.answer("accept");
		expect([accepted.status, accepted.location]).toEqual([303, asked.onAccept]);
		expect(await given.granted("app", "alice")).toEqual(["read", "write"]);
		expect((await alice.answer("accept")).status).toBe(303);
		expect((await alice.answer("deny")).status).toBe(400);
	});

	it("sends a refusal on without granting anything", async () => {
		const { pendingFor, given } = await serve();
		const denied = await (await pendingFor("alice")).answer("deny");
		expect([denied.status, denied.location]).toEqual([303, asked.onDeny]);
		expect(await given.granted("app", "alice")).toEqual([]);
	});

	it("records each decision it completes, with the subject, the client, the source and the range", async () => {
		const { pendingFor, events } = await serve();
		const accepted = await pendingFor("alice");
		const denied = await pendingFor("alice", { ...asked, range: ["admin"] });
		await accepted.answer("accept");
		await denied.answer("deny");
		await denied.answer("accept");
		const by = { client: "app", source: "198.51.100.1" };
		expect(events).toEqual([
			{
				kind: "consent.granted",
				at: now,
				subject: "alice",
				attributes: { ...by, scopes: "read write" },
			},
			{ kind: "consent.denied", at: now, subject: "alice", attributes: { ...by, scopes: "admin" } },
		]);
	});

	it("leaves the source out when a trusted proxy did not say who sent the answer", async () => {
		const { pendingFor, events } = await serve();
		const alice = await pendingFor("alice");
		await alice.answer("deny", { origin: "https://as.example", "x-forwarded-for": "127.0.0.1" });
		expect(events.map((event) => event.attributes)).toStrictEqual([
			{ client: "app", scopes: "read write" },
		]);
	});

	it("keeps the challenge when the answer is refused for CSRF or a bad decision", async () => {
		const { pendingFor } = await serve();
		const alice = await pendingFor("alice");
		expect((await alice.answer("accept", { origin: "https://evil.example" })).status).toBe(403);
		expect((await alice.answer("maybe")).status).toBe(400);
		expect((await alice.answer("accept")).status).toBe(303);
	});

	it("takes the answer as JSON too, a member that is not a string counting as absent", async () => {
		const { pendingFor, call, given } = await serve();
		const { cookie, challenge } = await pendingFor("alice");
		const json = { "content-type": "application/json", origin: "https://as.example" };
		const send = (body: string, headers = json) => call("POST", cookie, body, headers);
		expect((await send(JSON.stringify({ challenge, decision: ["accept"] }))).status).toBe(400);
		expect(
			(await send(JSON.stringify({ challenge: [challenge], decision: "accept" }))).body,
		).toEqual({ error: "unknown_challenge" });
		const plain = { "content-type": "text/plain", origin: "https://as.example" };
		expect((await send(JSON.stringify({ challenge, decision: "accept" }), plain)).status).toBe(415);
		const accepted = await send(JSON.stringify({ challenge, decision: "accept" }));
		expect([accepted.status, accepted.location]).toEqual([303, asked.onAccept]);
		expect(await given.granted("app", "alice")).toEqual(["read", "write"]);
	});

	it("answers only the session that parked the challenge", async () => {
		const { sessionFor, pendingFor, call } = await serve();
		const alice = await pendingFor("alice");
		const { challenge } = alice;
		const again = await sessionFor("alice");
		const bob = await sessionFor("bob");
		expect((await call("POST", again.cookie, { challenge, decision: "accept" })).status).toBe(400);
		expect((await call("POST", bob.cookie, { challenge, decision: "accept" })).status).toBe(400);
		expect((await call("POST", "", { challenge, decision: "accept" })).status).toBe(401);
		expect((await alice.answer("accept")).status).toBe(303);
	});

	it("refuses a repeated field, and answers uncached", async () => {
		const { pendingFor, call } = await serve();
		const { cookie, challenge: c } = await pendingFor("alice");
		const repeated = await call("POST", cookie, `challenge=${c}&challenge=${c}&decision=accept`);
		expect([repeated.status, repeated.cacheControl, repeated.body]).toEqual([
			400,
			"no-store",
			{ error: "repeated_parameter" },
		]);
	});

	it("lets a challenge be used until just before its expiry, and not at it", async () => {
		const { pendingFor } = await serve();
		const alice = await pendingFor("alice");
		now += 59_999;
		expect((await alice.show()).body.expires_in).toBe(1);
		expect((await alice.answer("accept")).status).toBe(303);
		const next = await pendingFor("alice");
		now += 60_000;
		expect((await next.answer("accept")).status).toBe(400);
	});
});

describe("consent: grants", () => {
	it("grows a grant as a union, through a lost answer", async () => {
		const { grants, given } = await serve();
		await given.grant("app", "alice", ["read"]);
		grants.loseNext("change");
		await expect(given.grant("app", "alice", ["write"])).rejects.toThrow(Unavailable);
		await given.grant("app", "alice", ["write"]);
		expect(await given.granted("app", "alice")).toEqual(["read", "write"]);
		expect(await given.granted("other", "alice")).toEqual([]);
	});

	it("keeps one grant per subject and client, whatever characters either holds", async () => {
		const { given } = await serve();
		await given.grant("app", "alice", ["read"]);
		expect(await given.granted("pp", "alicea")).toEqual([]);
		expect(await given.granted("app", "alice")).toEqual(["read"]);
	});

	it("covers a range only where a grant was recorded, the empty range included", async () => {
		const { given } = await serve();
		expect(await given.covers("app", "alice", [])).toBe(false);
		await given.grant("app", "alice", []);
		expect(await given.covers("app", "alice", [])).toBe(true);
		expect(await given.covers("app", "alice", ["read"])).toBe(false);
		await given.grant("app", "alice", ["read"]);
		expect(await given.covers("app", "alice", ["read"])).toBe(true);
	});
});

describe("consent under store faults and races", () => {
	it.each([
		["accept", asked.onAccept, ["read", "write"]],
		["deny", asked.onDeny, []],
	] as const)(
		"finishes a %s resent after a lost reply, the other decision getting nothing",
		async (decision, to, granted) => {
			const { asks, pendingFor, given } = await serve();
			const alice = await pendingFor("alice");
			asks.loseNext("change");
			const failed = await alice.answer(decision);
			expect([failed.status, failed.location]).toEqual([503, null]);
			const resent = await alice.answer(decision);
			expect([resent.status, resent.location]).toEqual([303, to]);
			expect(await given.granted("app", "alice")).toEqual(granted);
			expect((await alice.answer(decision === "accept" ? "deny" : "accept")).status).toBe(400);
			expect((await alice.show()).status).toBe(400);
		},
	);

	it("lets only one of two concurrent answers to a pending consent take effect", async () => {
		const { pendingFor, given, events } = await serve();
		const alice = await pendingFor("alice");
		const [accepted, denied] = await Promise.all([alice.answer("accept"), alice.answer("deny")]);
		expect([accepted.status, denied.status].sort()).toEqual([303, 400]);
		const won = accepted.status === 303;
		expect(await given.granted("app", "alice")).toEqual(won ? ["read", "write"] : []);
		expect(events.map((event) => event.kind)).toEqual([won ? "consent.granted" : "consent.denied"]);
	});

	it("takes no effect from an answer whose mark loses the race to the other decision", async () => {
		const { asks, pendingFor, given, events } = await serve();
		const alice = await pendingFor("alice");
		asks.stand.raceNextChange((record) => ({ ...record, answer: "deny" }) as never);
		expect((await alice.answer("accept")).status).toBe(400);
		expect(await given.granted("app", "alice")).toEqual([]);
		expect(events).toEqual([]);
	});

	it("answers 503 when the grant cannot be written, and a resend completes it", async () => {
		const { grants, pendingFor, given } = await serve();
		const alice = await pendingFor("alice");
		grants.down.failNext("change");
		const failed = await alice.answer("accept");
		expect([failed.status, failed.location]).toEqual([503, null]);
		expect((await alice.answer("accept")).status).toBe(303);
		expect(await given.granted("app", "alice")).toEqual(["read", "write"]);
	});

	it("counts a pending consent's time on the composition's clock, though the store's falls behind", async () => {
		const { pendingFor } = await serve();
		const alice = await pendingFor("alice");
		behind.ms = 30_000;
		now += 20_000;
		expect((await alice.show()).body.expires_in).toBe(40);
		now += 40_000;
		expect((await alice.show()).status).toBe(400);
		expect((await alice.answer("accept")).status).toBe(400);
	});

	it("widens a grant another request changed or saved first", async () => {
		const { grants, given } = await serve();
		grants.beforeNext("create", () => given.grant("app", "alice", ["admin"]));
		await given.grant("app", "alice", ["read"]);
		expect(await given.granted("app", "alice")).toEqual(["admin", "read"]);
		grants.stand.raceNextChange((record) => [...(record as unknown as string[]), "other"] as never);
		await given.grant("app", "alice", ["write"]);
		expect(await given.granted("app", "alice")).toEqual(["admin", "other", "read", "write"]);
		expect(await given.granted("app", "bob")).toEqual([]);
	});

	it("answers 503 when the grant store cannot tell, and refuses an ask it cannot park", async () => {
		const { grants, asks, pendingFor, given } = await serve();
		const alice = await pendingFor("alice");
		grants.down.failNext("read");
		const shown = await alice.show();
		expect([shown.status, shown.body]).toEqual([503, { error: "temporarily_unavailable" }]);
		asks.down.failNext("create");
		await expect(given.ask(alice.session, asked)).rejects.toThrow(Unavailable);
	});

	it("refuses an ask whose key is taken, and a grant gone between its save and its widening", async () => {
		const { grants, asks, sessionFor, given } = await serve();
		const alice = await sessionFor("alice");
		asks.beforeNext("create", (key) => asks.stand.records.create(key, {} as StoredAsk, 1000));
		await expect(given.ask(alice.session, asked)).rejects.toThrow(Unavailable);
		grants.beforeNext("create", async () => {
			await given.grant("app", "alice", ["admin"]);
			grants.beforeNext("change", (key) => grants.stand.records.remove(key));
		});
		await expect(given.grant("app", "alice", ["read"])).rejects.toThrow(Unavailable);
	});
});

describe("consent's records", () => {
	it("keeps a grant without end, to the subject of the session that asked", async () => {
		const { pendingFor, given } = await serve();
		expect((await (await pendingFor("bob")).answer("accept")).status).toBe(303);
		now += 10 * 365 * 86_400_000;
		expect(await given.granted("app", "bob")).toEqual(["read", "write"]);
		expect(await given.granted("app", "alice")).toEqual([]);
	});

	it("leaves a pending consent to the store for exactly its time", async () => {
		const { asks, pendingFor } = await serve();
		await pendingFor("alice");
		const [key] = asks.keys as [string];
		now += 59_999;
		expect(asks.stand.peek(key)).toBeDefined();
		now += 1;
		expect(asks.stand.peek(key)).toBeUndefined();
	});
});

describe("consent's sections", () => {
	it("takes first-party only from clients the operator registered", async () => {
		const client = (registered: boolean, value: unknown) => ({
			id: "c",
			kind: "public" as const,
			method: "none",
			registered,
			section: <T>() => ({ "first-party": value }) as T,
		});
		expect(isFirstParty(client(true, true))).toBe(true);
		expect(isFirstParty(client(false, true))).toBe(false);
		expect(isFirstParty(client(true, false))).toBe(false);
		const schema = clientSection.schema["~standard"];
		expect(await schema.validate({})).toEqual({ value: { "first-party": false } });
		expect((await schema.validate({ "first-party": true, other: 1 })).issues).toBeDefined();
	});

	it("makes what the consent page shows of a client: the name trimmed and cut to 200 characters, the page an https URL", async () => {
		const check = async (value: unknown) => {
			const result = await clientSection.schema["~standard"].validate(value);
			return result.issues ? "refused" : result.value;
		};
		expect(await check({ name: "\t Acme \n", host: "acme.example" })).toEqual({
			"first-party": false,
			name: "Acme",
			host: "acme.example",
		});
		const long = (await check({ name: "\u{1f600}".repeat(250), host: "a.example" })) as {
			name: string;
		};
		expect([...long.name]).toEqual(Array(200).fill("\u{1f600}"));
		const page = (uri: string) => check({ name: "Acme", uri, host: "acme.example" });
		expect(await page("https://acme.example/about")).toMatchObject({
			uri: "https://acme.example/about",
		});
		for (const uri of [
			"http://acme.example/",
			"javascript:alert(1)",
			"https://acme.example/\nx",
			"acme",
		]) {
			expect(await page(uri), uri).toBe("refused");
		}
		expect(await check({ name: " \t ", host: "acme.example" })).toBe("refused");
		expect(await check({ name: "Acme", host: "" })).toBe("refused");
		expect(await check({ name: "Acme", host: "acme.example\r\n" })).toBe("refused");
	});

	it("copies a metadata document's name, page and host, refusing a name absent, not a string or blank", async () => {
		const from = { id: "https://acme.example/client.json", host: "acme.example" };
		const copy = (document: Record<string, unknown>) =>
			clientSection.fromDocument?.(document, from);
		expect(clientSection.reads).toEqual(["client_name", "client_uri"]);
		for (const name of [undefined, 7, " \t\n "]) {
			expect(copy({ client_name: name }), String(name)).toEqual({ refused: "client_name" });
		}
		expect(copy({ client_name: " Acme ", client_uri: "http://acme.example/" })).toEqual({
			value: { name: " Acme ", uri: "http://acme.example/", host: "acme.example" },
		});
		expect(copy({ client_name: "Acme", client_uri: 7 })).toEqual({
			value: { name: "Acme", uri: 7, host: "acme.example" },
		});
		const copied = copy({
			client_name: "Acme",
			"first-party": true,
			first_party: true,
			host: "evil.example",
			logo_uri: "https://acme.example/logo.png",
		});
		expect(copied).toEqual({ value: { name: "Acme", host: "acme.example" } });
		const value = copied !== undefined && "value" in copied ? copied.value : undefined;
		expect(await clientSection.schema["~standard"].validate(value)).toEqual({
			value: { "first-party": false, name: "Acme", host: "acme.example" },
		});
	});

	it("takes a challenge's time written with its unit, in whole seconds from 1m to 1h, 10m unless set", () => {
		const page = "https://as.example/consent";
		const takes = (value: unknown) =>
			section.safeParse({ page, "challenge-lifetime": value }).success;
		expect(["1m", "60s", "1h"].map(takes)).toEqual([true, true, true]);
		expect(["59s", "3601s", "60500ms", 600, "600"].map(takes)).toEqual([
			false,
			false,
			false,
			false,
			false,
		]);
		expect(section.parse({ page })["challenge-lifetime"]).toBe(600);
	});

	it("takes a page only as an https URL kept as written: no userinfo, no fragment", () => {
		const page = (value: string) => section.safeParse({ page: value }).success;
		expect(page("https://as.example/consent?ui=1")).toBe(true);
		for (const value of [
			"http://as.example/consent",
			"https://u@as.example/consent",
			"https://as.example/#/consent",
		]) {
			expect(page(value), value).toBe(false);
		}
	});
});
