import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Runtime,
} from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { type Narrower, outbound } from "@mod/outbound";
import outboundModule from "@mod/outbound/module";
import {
	credentialPolicy,
	credentialRefusalText,
	outboundRefusals,
	policyOf,
	policySettings,
} from "@mod/outbound-policy";
import secretHashModule from "@mod/secret-hash/module";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { type Ledger, ledgers, userAttribute, users } from "@mod/users";
import usersModule from "@mod/users/module";
import { ledgerContract, memoryUsersStores, testUser, usersContract } from "@mod/users/testing";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import usersHttp from "../src/module.ts";

const credential = randomBytes(32).toString("hex");
/** Alice as the ledger answers her. */
const alice = { id: "s-alice", username: "alice", name: "Alice", email: "Alice@example.com" };

interface Asked {
	readonly method: string;
	/** The path as sent, percent-encoding kept. */
	readonly path: string;
	readonly headers: Readonly<Record<string, string | string[] | undefined>>;
	readonly body: string;
}
interface Answer {
	readonly status: number;
	readonly json?: unknown;
	readonly text?: string;
	readonly headers?: Readonly<Record<string, string>>;
	readonly delayMs?: number;
}

/**
 * The ledger in the request shape: alice at `/ledger/authenticate`, behind the credential. It refuses
 * an unknown identifier and a wrong password with 401, without a Bearer challenge. At
 * `/ledger/subject` it finds alice, refuses the suspended `s-gone` with a 410 saying `gone`, and
 * knows no one else, saying `not_found`. At `/ledger/upstream` it ties Apple's `apple-alice` to
 * alice and refuses `apple-gone` alike. Any other route is a bare 404.
 */
const notFound: Answer = { status: 404, json: { error: "not_found" } };
const gone: Answer = { status: 410, json: { error: "gone" } };

function aliceLedger(asked: Asked): Answer {
	if (asked.headers.authorization !== `Bearer ${credential}`) {
		return { status: 401, headers: { "www-authenticate": 'Bearer error="invalid_token"' } };
	}
	if (asked.method === "POST" && asked.path === "/ledger/authenticate") {
		const { email, password } = JSON.parse(asked.body);
		if (email !== "alice") return { status: 401 };
		return password === "correct horse" ? { status: 200, json: alice } : { status: 401 };
	}
	if (asked.method === "POST" && asked.path === "/ledger/subject") {
		const { subject } = JSON.parse(asked.body);
		if (subject === "s-gone") return gone;
		return subject === "s-alice" ? { status: 200, json: alice } : notFound;
	}
	if (asked.method === "POST" && asked.path === "/ledger/upstream") {
		const { idp, subject } = JSON.parse(asked.body);
		if (idp === "apple" && subject === "apple-gone") return gone;
		return idp === "apple" && subject === "apple-alice" ? { status: 200, json: alice } : notFound;
	}
	return { status: 404 };
}

let script: (asked: Asked) => Answer = aliceLedger;
const received: Asked[] = [];
const server = createServer((req, res) => {
	let body = "";
	req.on("data", (chunk: Buffer) => {
		body += chunk;
	});
	req.on("end", () => {
		const asked = { method: req.method ?? "", path: req.url ?? "", headers: req.headers, body };
		received.push(asked);
		// A script that cannot read the request answers 400, rather than leaving the request open.
		const answer = (() => {
			try {
				return script(asked);
			} catch {
				return { status: 400 } as Answer;
			}
		})();
		setTimeout(() => {
			res.writeHead(answer.status, {
				...(answer.json === undefined ? {} : { "content-type": "application/json" }),
				...answer.headers,
			});
			res.end(answer.json === undefined ? (answer.text ?? "") : JSON.stringify(answer.json));
		}, answer.delayMs ?? 0);
	});
});
let pair = "";
beforeAll(async () => {
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	pair = `127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((done) => server.close(() => done())));
beforeEach(() => {
	script = aliceLedger;
	received.length = 0;
	logged.length = 0;
});

const logged: unknown[][] = [];
const runtime: Runtime = {
	clock: { now: () => Date.now() },
	random: { bytes: (n) => new Uint8Array(n) },
	log: {
		trace: () => {},
		debug: () => {},
		info: () => {},
		warn: (...line) => logged.push(line),
		error: (...line) => logged.push(line),
		fatal: (...line) => logged.push(line),
	},
};
const settings = (extra: Record<string, unknown> = {}) => ({
	"verify-url": `http://${pair}/ledger/authenticate`,
	credential,
	...extra,
});
const collected = contract<readonly Ledger[]>("test.ledgers");
const collector = defineModule(
	{ name: "test-collector", replicaSafe: false, takes: [ledgers] },
	(m) => [m.provide(collected).by((c) => c.collect(ledgers))],
);
const boot = (
	section: unknown,
	registered: unknown[] = [],
	allow = ["127.0.0.1"],
	loopback = [pair],
) =>
	assemble({
		modules: [
			outboundModule,
			tlsOptionsForTests,
			usersModule,
			secretHashModule,
			memoryUsersStores().module,
			usersHttp,
			collector,
		],
		config: {
			...kernelConfig(),
			outbound: { allow, "plain-loopback": loopback },
			users: { registered },
			...(section === undefined ? {} : { "users-http": section }),
		},
		runtime,
	});
/** The contributed ledger itself, and users answering from it. */
async function open(extra?: Record<string, unknown>, allow?: string[]) {
	const app = await boot(settings(extra), [], allow);
	const [ledger] = app.get(collected);
	if (!ledger) throw new Error("no ledger contributed");
	return { ledger, users: app.get(users) };
}
/** Each request the ledger received, by the shape users-http sends. */
const shapeOf = (asked: Asked) =>
	`${asked.method} ${asked.path.split("/").slice(0, 3).join("/")} ${Object.keys(
		asked.body === "" ? {} : JSON.parse(asked.body),
	).join(",")}`;
const shapes = (from: number) => received.slice(from).map(shapeOf);

ledgerContract("users-http against a fake ledger", {
	open: async () => {
		const { ledger } = await open();
		const checks: string[] = [];
		const counted: Ledger = {
			verify: async (identifier, password) => {
				const before = received.length;
				try {
					return await ledger.verify(identifier, password);
				} finally {
					checks.push(...shapes(before));
				}
			},
			bySubject: ledger.bySubject,
		};
		return { ledger: counted, checks };
	},
	unanswerableBySubject: true,
});

ledgerContract("users-http looking users up by subject and upstream identity", {
	open: async () => {
		const { ledger } = await open({
			"subject-url": `http://${pair}/ledger/subject`,
			"upstream-url": `http://${pair}/ledger/upstream`,
		});
		const checks: string[] = [];
		return {
			ledger: {
				...ledger,
				verify: async (identifier, password) => {
					const before = received.length;
					try {
						return await ledger.verify(identifier, password);
					} finally {
						checks.push(...shapes(before));
					}
				},
			},
			checks,
		};
	},
	upstreamOfAlice: { idp: "apple", subject: "apple-alice" },
});

async function linked() {
	const { users: u } = await open();
	await u.link("s-alice", { idp: "example", subject: "u-alice" });
	return u;
}
usersContract("users with users-http against a fake ledger", {
	open: linked,
	openCounting: async () => {
		const u = await linked();
		const checks: string[] = [];
		const verify = u.verify;
		return {
			users: {
				...u,
				verify: async (identifier, password) => {
					const before = received.length;
					try {
						return await verify(identifier, password);
					} finally {
						checks.push(...shapes(before));
					}
				},
			},
			checks,
		};
	},
	writtenLinksOnly: true,
	unanswerableBySubject: true,
});

/** Tokens cut from this hold many byte values, so only their length and form are at stake. */
const varied = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

describe("users-http", () => {
	it("asks the ledger in the stated shape, the password only in the body", async () => {
		const { ledger } = await open();
		await ledger.verify("alice", "correct horse");
		const [verify] = received;
		expect(verify?.method).toBe("POST");
		expect(verify?.path).toBe("/ledger/authenticate");
		expect(verify?.headers).toMatchObject({
			authorization: `Bearer ${credential}`,
			accept: "application/json",
			"content-type": "application/json",
		});
		expect(JSON.parse(verify?.body ?? "")).toEqual({ email: "alice", password: "correct horse" });
		script = () => ({ status: 200, json: alice });
		const queried = await open({ "verify-url": `http://${pair}/ledger/authenticate?realm=a` });
		await queried.ledger.verify("alice", "correct horse");
		expect(received[1]?.path).toBe("/ledger/authenticate?realm=a");
	});

	it("sends no credential when none is set, and then reads a challenged 401 as none, and a 403 as unavailable", async () => {
		const app = await boot({ "verify-url": `http://${pair}/ledger/authenticate` });
		const [ledger] = app.get(collected);
		script = () => ({ status: 401, headers: { "www-authenticate": "Bearer" } });
		expect(await ledger?.verify("alice", "x")).toEqual({ kind: "none" });
		script = () => ({ status: 403, headers: { "www-authenticate": "Bearer" } });
		await expect(ledger?.verify("alice", "x")).rejects.toSatisfy(isUnavailable);
		expect(received.map((r) => r.headers.authorization)).toEqual([undefined, undefined]);
	});

	it("answers every subject unanswerable, without asking the ledger", async () => {
		const { ledger, users: u } = await open();
		for (const subject of ["s-alice", "s-nobody"]) {
			expect(await ledger.bySubject(subject)).toEqual({ kind: "unanswerable" });
			expect(await u.bySubject(subject)).toEqual({ kind: "unanswerable" });
		}
		expect(received).toEqual([]);
	});

	it("answers none to a 401 alone: a 403, which a proxy before the ledger may send while it fails, is unavailable", async () => {
		const { ledger } = await open();
		expect(await ledger.verify("nobody", "x")).toEqual({ kind: "none" });
		expect(await ledger.verify("alice", "x")).toEqual({ kind: "none" });
		// Unavailable, login-password answers 503 and counts no attempt: no account waits for a proxy's fault.
		script = () => ({ status: 403 });
		await expect(ledger.verify("alice", "x")).rejects.toSatisfy(isUnavailable);
		const challenges = [
			'Basic realm="x, Bearer y"',
			"Basic realm=x, bearer=1",
			"Basic realm=x, bearer =1",
			"Basic realm=x, title=bearer",
		];
		for (const challenge of challenges) {
			script = () => ({ status: 401, headers: { "www-authenticate": challenge } });
			expect(await ledger.verify("alice", "x"), challenge).toEqual({ kind: "none" });
		}
	});

	it("answers none to a 404 or a 410 saying it knows no such user, as a lookup does, unlogged", async () => {
		const { ledger } = await open();
		for (const answer of [notFound, gone]) {
			script = () => answer;
			expect(await ledger.verify("alice", "correct horse"), JSON.stringify(answer)).toEqual({
				kind: "none",
			});
		}
		expect(logged).toEqual([]);
	});

	it("answers unavailable to a 404 or a 410 that does not say it knows no such user, logging its status", async () => {
		const { ledger } = await open();
		const answers: Answer[] = [
			{ status: 404 },
			{ status: 410 },
			{ status: 404, text: "not_found" },
			{ status: 404, json: { error: "gone" } },
			{ status: 410, json: { error: "not_found" } },
			{ status: 404, json: ["not_found"] },
		];
		for (const answer of answers) {
			script = () => answer;
			await expect(
				ledger.verify("alice", "correct horse"),
				JSON.stringify(answer),
			).rejects.toSatisfy(isUnavailable);
		}
		expect(logged).toEqual(
			answers.map(({ status }) => ["users-http.ledger_failed", { status, reason: "unmarked" }]),
		);
	});

	it("answers unavailable to a 401 or 403 that challenges its credential as Bearer", async () => {
		const { ledger } = await open();
		const challenges = [
			"Bearer",
			'Bearer error="invalid_token"',
			'Basic realm="x", bearer',
			"Bearer , Basic",
		];
		for (const status of [401, 403]) {
			for (const challenge of challenges) {
				script = () => ({ status, headers: { "www-authenticate": challenge } });
				const name = `${status} ${challenge}`;
				await expect(ledger.verify("alice", "x"), name).rejects.toSatisfy(isUnavailable);
			}
		}
	});

	it("answers a refusal, a failure, a redirect or an unreadable answer as unavailable, showing nothing the ledger sent", async () => {
		const failures: Record<string, Answer> = {
			"credential refused": {
				status: 401,
				text: "ledger detail",
				headers: { "www-authenticate": 'Bearer error="invalid_token"' },
			},
			"credential refused with 403": {
				status: 403,
				text: "ledger detail",
				headers: { "www-authenticate": "Bearer" },
			},
			"server error": { status: 500, text: "ledger detail" },
			redirect: { status: 302, headers: { location: `http://${pair}/elsewhere` } },
			"no content": { status: 204 },
			"not JSON": { status: 200, text: "ledger detail" },
			"an array": { status: 200, json: [alice] },
		};
		for (const [name, answer] of Object.entries(failures)) {
			script = () => answer;
			logged.length = 0;
			const { ledger, users: u } = await open();
			const error = await ledger.verify("alice", "pw-1").then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(isUnavailable(error), name).toBe(true);
			expect(String((error as Error).message), name).not.toMatch(/ledger detail|pw-1|elsewhere/);
			await expect(u.verify("alice", "pw-1"), name).rejects.toSatisfy(isUnavailable);
			expect(JSON.stringify(logged), name).not.toMatch(/ledger detail|pw-1|secret/);
		}
		expect(received.some((r) => r.path === "/elsewhere")).toBe(false);
	});

	it("logs the status of a ledger's failure, and nothing it sent", async () => {
		script = () => ({ status: 500, text: "ledger detail" });
		const { ledger } = await open();
		await expect(ledger.verify("alice", "pw-1")).rejects.toSatisfy(isUnavailable);
		expect(logged).toEqual([["users-http.ledger_failed", { status: 500 }]]);
	});

	it("logs the kind of each other failure, and nothing it sent", async () => {
		const cases: [string, () => Promise<unknown>, Record<string, unknown>][] = [
			[
				"a name allowed that resolves to a special address",
				async () => {
					const named = `https://localhost:${pair.split(":")[1]}/ledger/authenticate`;
					return (await open({ "verify-url": named }, ["localhost"])).ledger.verify(
						"alice",
						"pw-1",
					);
				},
				{ reason: "special-address" },
			],
			[
				"credential refused",
				async () => {
					script = () => ({
						status: 401,
						text: "ledger detail",
						headers: { "www-authenticate": "Bearer" },
					});
					return (await open()).ledger.verify("alice", "pw-1");
				},
				{ reason: "credential-refused" },
			],
			[
				"redirect",
				async () => {
					script = () => ({ status: 302, headers: { location: `http://${pair}/elsewhere` } });
					return (await open()).ledger.verify("alice", "pw-1");
				},
				{ reason: "redirect" },
			],
			[
				"no answer in time",
				async () => {
					script = (asked) => ({ ...aliceLedger(asked), delayMs: 300 });
					return (await open({ timeout: "50ms" })).ledger.verify("alice", "correct horse");
				},
				{ reason: "timeout" },
			],
			[
				"an answer past its size",
				async () => {
					script = () => ({ status: 200, json: { ...alice, name: "x".repeat(200) } });
					return (await open({ "max-response-size": "100B" })).ledger.verify("alice", "pw-1");
				},
				{ reason: "too-large" },
			],
			[
				"not JSON",
				async () => {
					script = () => ({ status: 200, text: "ledger detail" });
					return (await open()).ledger.verify("alice", "pw-1");
				},
				{ reason: "malformed" },
			],
			[
				"an id that is no subject",
				async () => {
					script = () => ({ status: 200, json: { ...alice, id: "x".repeat(256) } });
					return (await open()).ledger.verify("alice", "pw-1");
				},
				{ reason: "malformed" },
			],
			[
				"no username",
				async () => {
					script = () => ({ status: 200, json: { id: "s-alice" } });
					return (await open()).ledger.verify("alice", "pw-1");
				},
				{ reason: "malformed" },
			],
		];
		for (const [name, call, fields] of cases) {
			script = aliceLedger;
			logged.length = 0;
			await expect(call(), name).rejects.toSatisfy(isUnavailable);
			expect(logged, name).toEqual([["users-http.ledger_failed", fields]]);
		}
	});

	it("answers unavailable past its own time or size, never none", async () => {
		script = (asked) => ({ ...aliceLedger(asked), delayMs: 300 });
		const slow = await open({ timeout: "50ms" });
		await expect(slow.ledger.verify("alice", "correct horse")).rejects.toSatisfy(isUnavailable);
		script = () => ({ status: 200, json: { ...alice, name: "x".repeat(200) } });
		const large = await open({ "max-response-size": "100B" });
		await expect(large.ledger.verify("alice", "correct horse")).rejects.toSatisfy(isUnavailable);
		const roomy = await open({ "max-response-size": "1000B" });
		expect((await roomy.ledger.verify("alice", "correct horse")).kind).toBe("user");
	});

	it("refuses a malformed user as unavailable [oidc-core-2-c]", async () => {
		const malformed: Record<string, unknown> = {
			"empty id": { ...alice, id: "" },
			"no id": { username: "alice" },
			"id not a string": { ...alice, id: 7 },
			"id past 255 characters": { ...alice, id: "x".repeat(256) },
			"id outside ASCII": { ...alice, id: "s-alicé" },
			"empty username": { ...alice, username: "" },
			"no username": { id: "s-alice" },
			"username not a string": { ...alice, username: ["alice"] },
		};
		for (const [name, json] of Object.entries(malformed)) {
			script = () => ({ status: 200, json });
			const { ledger } = await open();
			await expect(ledger.verify("alice", "p"), name).rejects.toSatisfy(isUnavailable);
		}
		script = () => ({ status: 200, json: { ...alice, id: "x".repeat(255) } });
		const { ledger } = await open();
		expect(await ledger.verify("alice", "p")).toMatchObject({ user: { subject: "x".repeat(255) } });
	});

	it("hands over the id as the subject and the user's fields as frozen attributes under users' names, nothing else", async () => {
		const fields = {
			email: "a@example.com",
			name: "Alice",
			picture: "https://example.com/a.png",
			groups: ["staff"],
		};
		const answered = {
			id: "s-alice",
			username: "alice",
			...fields,
			emailVerified: false,
			mfaEnrolled: true,
			role: "admin",
		};
		script = () => ({ status: 200, json: answered });
		const { ledger } = await open();
		const found = await ledger.verify("alice", "p");
		const attributes = {
			[userAttribute.email]: fields.email,
			[userAttribute.name]: fields.name,
			[userAttribute.picture]: fields.picture,
			[userAttribute.groups]: fields.groups,
			[userAttribute.emailVerified]: false,
		};
		expect(found).toEqual({ kind: "user", user: { subject: "s-alice", attributes } });
		const groups = found.kind === "user" && found.user.attributes[userAttribute.groups];
		expect(Object.isFrozen(groups)).toBe(true);
		const email = "alice@example.test";
		for (const emailVerified of [true, "true", 1, null]) {
			script = () => ({
				status: 200,
				json: { id: "s-alice", username: "alice", email, emailVerified },
			});
			const verified =
				typeof emailVerified === "boolean" ? { [userAttribute.emailVerified]: emailVerified } : {};
			expect(await ledger.verify("alice", "p"), String(emailVerified)).toEqual({
				kind: "user",
				user: { subject: "s-alice", attributes: { [userAttribute.email]: email, ...verified } },
			});
		}
		// Whether an email is verified says nothing without the email it is about.
		script = () => ({
			status: 200,
			json: { id: "s-alice", username: "alice", emailVerified: true },
		});
		expect(await ledger.verify("alice", "p")).toEqual({
			kind: "user",
			user: { subject: "s-alice", attributes: {} },
		});
		script = () => ({
			status: 200,
			json: { id: "s-alice", username: "alice", email_verified: true },
		});
		expect(await ledger.verify("alice", "p")).toEqual({
			kind: "user",
			user: { subject: "s-alice", attributes: {} },
		});
		script = () => ({ status: 200, json: { id: "s-alice", username: "alice" } });
		expect(await ledger.verify("alice", "p")).toEqual({
			kind: "user",
			user: { subject: "s-alice", attributes: {} },
		});
	});

	it("refuses to start without a URL it takes or with a malformed credential, never showing the credential", async () => {
		const refusals: unknown[] = [
			undefined,
			{ credential },
			{ url: `http://${pair}/ledger/authenticate`, credential },
			settings({ credential: "" }),
			settings({ credential: `has ${credential} space` }),
			settings({ credential: `Bearer ${credential}` }),
			settings({ credential: `${credential}\n` }),
			settings({ credential: `${credential}é` }),
			settings({ credential: "0123456789abcdef".repeat(4).slice(0, 62) }),
			settings({ credential: `REPLACE-${"x".repeat(60)}` }),
			settings({ credential: `${credential}@` }),
			settings({ credential: varied.slice(0, 42) }),
			settings({ credential: varied.slice(0, 32) }),
			settings({ "verify-url": `http://${pair}/ledger/authenticate#x` }),
			settings({ "verify-url": `http://user:secret-9@${pair}/ledger/authenticate` }),
			settings({ "verify-url": `ftp://${pair}/ledger/authenticate` }),
			settings({ "verify-url": `HTTPS://${pair}/ledger/authenticate` }),
			settings({ timeout: "0ms" }),
			settings({ timeout: "60001ms" }),
			settings({ timeout: 50 }),
			settings({ timeout: "50" }),
			settings({ "max-response-size": "0B" }),
			settings({ "max-response-size": "16777217B" }),
			settings({ "max-response-size": 100 }),
			settings({ "timeout-ms": 50 }),
			settings({ "max-response-bytes": 100 }),
			settings({ extra: true }),
		];
		for (const section of refusals) {
			const error = await boot(section).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(error, JSON.stringify(section)).toBeInstanceOf(BootRefused);
			const shown = (error as BootRefused).refusals.map((r) => `${r.where} ${r.reason}`).join("\n");
			const given = (section as { credential?: string } | undefined)?.credential;
			for (const secret of [given, credential, "secret-9"]) {
				if (secret) expect(shown, JSON.stringify(section)).not.toContain(secret);
			}
		}
	});

	it("names verify-url as the operator's own, at boot and on each request, so a ledger at a private address is reached", async () => {
		const checked: (Narrower | undefined)[] = [];
		const sent: (Narrower | undefined)[] = [];
		const recording = defineModule({ name: "outbound", replicaSafe: false, takes: [] }, (m) => [
			m.provide(outbound).by(() => ({
				fetch: async (_url, _request, narrower) => {
					sent.push(narrower);
					return {
						status: 200,
						headers: new Map(),
						body: new TextEncoder().encode(JSON.stringify(alice)),
					};
				},
			})),
			m.provide(outboundRefusals).by(() => ({
				explained: (_url, narrower) => {
					checked.push(narrower);
					return undefined;
				},
			})),
			m.provide(credentialPolicy).by(() => ({ refusalOf: () => undefined })),
		]);
		const app = await assemble({
			modules: [
				recording,
				usersModule,
				secretHashModule,
				memoryUsersStores().module,
				usersHttp,
				collector,
			],
			config: { ...kernelConfig(), users: { registered: [] }, "users-http": settings() },
			runtime,
		});
		await app.get(collected)[0]?.verify("alice", "correct horse");
		// Named by the URL itself, so only its origin is reached at a private address.
		const own = { internal: settings()["verify-url"] };
		expect(checked).toMatchObject([own]);
		expect(sent).toMatchObject([own]);
	});

	it("refuses to start on a verify-url outbound's policy refuses, saying which of its keys to set", async () => {
		const refused = [
			[
				["ledger.example"],
				`http://${pair}/ledger/authenticate`,
				"not-allowed: name the host in outbound.allow, or set outbound.allow-any-public",
			],
			[
				["127.0.0.1"],
				"http://127.0.0.1:8/ledger/authenticate",
				// The policy's own words for plain http, which outbound-policy's tests hold.
				policyOf(policySettings.parse({ allow: ["127.0.0.1"] })).explain(
					"http://127.0.0.1:8/ledger/authenticate",
				),
			],
		] as const;
		for (const [allow, url, reason] of refused) {
			await expect(
				boot(settings({ "verify-url": url }), [], [...allow]),
				url,
			).rejects.toMatchObject({
				refusals: [
					{
						where: "users-http.verify-url",
						reason: `outbound's destination policy refuses it: ${reason}`,
					},
				],
			});
		}
	});

	it("starts with a bare token of at least 32 bytes of key material, read in its least form", async () => {
		const taken = [
			"0123456789abcdef".repeat(4),
			varied.slice(0, 43),
			`${varied.slice(0, 43)}=`,
			varied.slice(20),
			`~${varied.slice(0, 30)}~`,
			`${varied.slice(0, 31)}.=`,
			`${varied.slice(0, 43)}===`,
			`${varied.slice(0, 40)}====`,
			`${varied.slice(0, 40)}=`,
			varied.slice(0, 41),
			`${varied.slice(0, 40)}+_`,
		];
		for (const token of taken) {
			await expect(boot(settings({ credential: token })), token).resolves.toBeDefined();
		}
	});

	it("refuses to start beside users in the settings", async () => {
		await expect(boot(settings(), [testUser("bob", "p")])).rejects.toBeInstanceOf(BootRefused);
	});
});

describe("users-http looking a user up by subject", () => {
	const subjectUrl = () => `http://${pair}/ledger/subject`;
	const looking = (extra: Record<string, unknown> = {}) =>
		open({ "subject-url": subjectUrl(), ...extra });

	it("posts the subject alone to subject-url as written, with the credential", async () => {
		const { ledger } = await looking({ "subject-url": `${subjectUrl()}?realm=a` });
		script = () => ({ status: 200, json: alice });
		await ledger.bySubject("s-alice");
		const [asked] = received;
		expect([asked?.method, asked?.path]).toEqual(["POST", "/ledger/subject?realm=a"]);
		expect(asked?.headers).toMatchObject({
			authorization: `Bearer ${credential}`,
			accept: "application/json",
			"content-type": "application/json",
		});
		expect(JSON.parse(asked?.body ?? "")).toEqual({ subject: "s-alice" });
	});

	it("hands over the user it finds, needing no username, and none for a 404 or a 410, unlogged", async () => {
		const { ledger } = await looking();
		expect(await ledger.bySubject("s-alice")).toEqual({
			kind: "user",
			user: {
				subject: "s-alice",
				attributes: { [userAttribute.name]: "Alice", [userAttribute.email]: "Alice@example.com" },
			},
		});
		script = () => ({ status: 200, json: { id: "s-alice" } });
		expect(await ledger.bySubject("s-alice")).toMatchObject({ kind: "user" });
		script = aliceLedger;
		expect(await ledger.bySubject("s-nobody")).toEqual({ kind: "none" });
		expect(await ledger.bySubject("s-gone")).toEqual({ kind: "none" });
		expect(logged).toEqual([]);
	});

	it("answers unavailable to a 401 or 403, challenged or not, and to every other answer it cannot read", async () => {
		const { ledger } = await looking();
		const answers: Answer[] = [
			{ status: 401 },
			{ status: 403 },
			{ status: 401, headers: { "www-authenticate": "Bearer" } },
			{ status: 201, json: alice },
			{ status: 204 },
			{ status: 429 },
			{ status: 500 },
			{ status: 302, headers: { location: `http://${pair}/ledger/elsewhere` } },
			{ status: 200, json: { username: "alice" } },
			{ status: 200, json: { id: "" } },
			{ status: 200, json: ["s-alice"] },
			{ status: 200, text: "s-alice" },
			// A 404 or 410 that does not say what it means: a wrong path, a gateway, a ledger hiding itself.
			{ status: 404 },
			{ status: 410 },
			{ status: 404, text: "not_found" },
			{ status: 404, json: { error: "gone" } },
			{ status: 410, json: { error: "not_found" } },
			{ status: 404, json: ["not_found"] },
		];
		for (const answer of answers) {
			script = () => answer;
			await expect(ledger.bySubject("s-alice"), JSON.stringify(answer)).rejects.toSatisfy(
				isUnavailable,
			);
		}
		expect(received.map((r) => r.path).filter((path) => path !== "/ledger/subject")).toEqual([]);
		expect(logged).toContainEqual(["users-http.ledger_failed", { status: 201 }]);
	});

	it("logs a lookup's 404 or 410 that does not say it knows no such user, with its status alone", async () => {
		const { ledger } = await looking();
		script = () => ({ status: 404, text: "ledger detail" });
		await expect(ledger.bySubject("s-alice")).rejects.toSatisfy(isUnavailable);
		script = () => ({ status: 410 });
		await expect(ledger.bySubject("s-alice")).rejects.toSatisfy(isUnavailable);
		expect(logged).toEqual([
			["users-http.ledger_failed", { status: 404, reason: "unmarked" }],
			["users-http.ledger_failed", { status: 410, reason: "unmarked" }],
		]);
	});

	it("answers no password without verify-url, asking nothing", async () => {
		const app = await boot({ "subject-url": subjectUrl(), credential });
		const [ledger] = app.get(collected);
		expect(await ledger?.verify("alice", "correct horse")).toEqual({ kind: "none" });
		expect(received).toEqual([]);
	});

	it("gives users the address the ledger states for a subject", async () => {
		const { users: u } = await looking();
		expect(await u.claimedContacts("s-alice")).toEqual([
			{ kind: "email", value: "Alice@example.com" },
		]);
	});

	it("refuses to start with no URL, or with a credential and URLs at two origins", async () => {
		// A second origin outbound takes: the next port at loopback, where nothing need answer.
		const otherPair = `127.0.0.1:${Number(pair.split(":")[1]) + 1}`;
		const other = `http://${otherPair}/ledger/subject`;
		const bootBoth = (section: unknown) => boot(section, [], undefined, [pair, otherPair]);
		for (const [section, where] of [
			[{ credential }, "users-http"],
			[settings({ "subject-url": other }), "users-http.credential"],
			[settings({ "subject-url": `https://${pair}/ledger/subject` }), "users-http.credential"],
		] as const) {
			const error = await bootBoth(section).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(error, JSON.stringify(section)).toBeInstanceOf(BootRefused);
			const refusals = (error as BootRefused).refusals;
			expect(refusals.map((r) => r.where)).toEqual([where]);
			expect(refusals.map((r) => r.reason).join()).not.toContain(credential);
		}
		await expect(boot(settings({ "subject-url": subjectUrl() }))).resolves.toBeDefined();
		await expect(
			bootBoth({ "verify-url": `http://${pair}/ledger/authenticate`, "subject-url": other }),
		).resolves.toBeDefined();
	});

	it("starts with its credential to a ledger at a plain-internal pair, and says how to name one where plain http is refused", async () => {
		const internal = "ledger.internal:9092";
		const at = (pairs: readonly string[]) =>
			assemble({
				modules: [
					outboundModule,
					tlsOptionsForTests,
					usersModule,
					secretHashModule,
					memoryUsersStores().module,
					usersHttp,
				],
				config: {
					...kernelConfig(),
					outbound: { allow: ["ledger.internal"], "plain-internal": pairs },
					"users-http": { "verify-url": `http://${internal}/verify`, credential },
				},
				runtime,
			});
		await expect(at([internal])).resolves.toBeDefined();
		await expect(at([])).rejects.toMatchObject({
			refusals: [
				{
					where: "users-http.verify-url",
					reason: expect.stringContaining("outbound.plain-internal"),
				},
			],
		});
	});

	it("says why its credential may not go in outbound-policy's words", async () => {
		for (const refusal of ["origins", "scheme"] as const) {
			const standIn = defineModule({ name: "outbound", replicaSafe: true, takes: [] }, (m) => [
				m.provide(outbound).by(() => ({
					fetch: async () => {
						throw new Error("never sent");
					},
				})),
				m.provide(outboundRefusals).by(() => ({ explained: () => undefined })),
				m.provide(credentialPolicy).by(() => ({ refusalOf: () => refusal })),
			]);
			await expect(
				assemble({
					modules: [standIn, usersModule, secretHashModule, memoryUsersStores().module, usersHttp],
					config: { ...kernelConfig(), "users-http": settings() },
					runtime,
				}),
				refusal,
			).rejects.toMatchObject({
				refusals: [{ where: "users-http.credential", reason: credentialRefusalText(refusal) }],
			});
		}
	});

	it("takes outbound's credential policy only with a credential, its takes naming it either way", async () => {
		const unused = async (section: unknown) =>
			(
				await takesUnused({
					modules: [
						outboundModule,
						tlsOptionsForTests,
						usersModule,
						secretHashModule,
						memoryUsersStores().module,
						usersHttp,
						collector,
					],
					config: {
						...kernelConfig(),
						outbound: { allow: ["127.0.0.1"], "plain-loopback": [pair] },
						"users-http": section,
					},
					runtime,
				})
			)["users-http"];
		expect(await unused(settings())).toBeUndefined();
		// The take is conditional, the takes static: outbound provides the policy beside the refusals
		// the module always takes, so wherever it boots the policy is there; without a credential it
		// is left untaken.
		const { credential: _, ...bare } = settings();
		expect(await unused(bare)).toEqual(["outbound.credentials"]);
	});

	it("refuses to start on a subject-url outbound's policy refuses, saying why", async () => {
		await expect(boot({ "subject-url": "https://ledger.example/subject" })).rejects.toMatchObject({
			refusals: [{ where: "users-http.subject-url", reason: expect.stringContaining("outbound") }],
		});
	});
});

describe("users-http looking a user up by upstream identity", () => {
	const upstreamUrl = () => `http://${pair}/ledger/upstream`;

	it("posts the IdP's name and the upstream subject apart to upstream-url as written, with the credential", async () => {
		const { ledger } = await open({ "upstream-url": `${upstreamUrl()}?realm=a` });
		script = () => ({ status: 200, json: alice });
		await ledger.byUpstream?.("apple", "apple-alice");
		const [asked] = received;
		expect([asked?.method, asked?.path]).toEqual(["POST", "/ledger/upstream?realm=a"]);
		expect(asked?.headers).toMatchObject({ authorization: `Bearer ${credential}` });
		expect(JSON.parse(asked?.body ?? "")).toEqual({ idp: "apple", subject: "apple-alice" });
	});

	it("answers none to a 404 or a 410, and unavailable to a 401, a 403 or anything else it cannot read", async () => {
		const { ledger } = await open({ "upstream-url": upstreamUrl() });
		expect(await ledger.byUpstream?.("apple", "apple-nobody")).toEqual({ kind: "none" });
		expect(await ledger.byUpstream?.("apple", "apple-gone")).toEqual({ kind: "none" });
		for (const answer of [
			{ status: 401 },
			{ status: 403 },
			{ status: 500 },
			{ status: 200, json: {} },
			{ status: 404 },
			{ status: 410 },
		]) {
			script = () => answer;
			await expect(
				ledger.byUpstream?.("apple", "apple-alice"),
				JSON.stringify(answer),
			).rejects.toSatisfy(isUnavailable);
		}
	});

	it("offers no lookup by upstream identity without upstream-url", async () => {
		const { ledger } = await open({ "subject-url": `http://${pair}/ledger/subject` });
		expect(ledger.byUpstream).toBeUndefined();
	});

	it("has users take the ledger's answer over a link users keeps", async () => {
		const { users: u } = await open({ "upstream-url": upstreamUrl() });
		await u.link("s-alice", { idp: "apple", subject: "apple-gone" });
		expect(await u.byUpstream("apple", "apple-gone")).toEqual({ kind: "none" });
		expect(await u.byUpstream("apple", "apple-alice")).toMatchObject({
			kind: "user",
			user: { subject: "s-alice" },
		});
	});

	it("counts upstream-url among the URLs a credential is sent to", async () => {
		const error = await boot(settings({ "upstream-url": `https://${pair}/ledger/upstream` })).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect((error as BootRefused).refusals.map((r) => r.where)).toEqual(["users-http.credential"]);
		await expect(boot({ "upstream-url": "https://ledger.example/upstream" })).rejects.toMatchObject(
			{
				refusals: [
					{ where: "users-http.upstream-url", reason: expect.stringContaining("outbound") },
				],
			},
		);
		await expect(boot({ "upstream-url": upstreamUrl() })).resolves.toBeDefined();
	});
});
