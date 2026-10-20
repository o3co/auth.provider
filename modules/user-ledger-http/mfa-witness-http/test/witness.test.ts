import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { type EnrollmentWitness, enrollmentWitnesses } from "@mod/mfa-witness";
import { enrollmentWitnessContract, witnessProblems } from "@mod/mfa-witness/testing";
import { type Narrower, outbound } from "@mod/outbound";
import outboundModule from "@mod/outbound/module";
import {
	credentialPolicy,
	credentialRefusalText,
	outboundLimits,
	outboundRefusals,
	policyOf,
	policySettings,
} from "@mod/outbound-policy";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import witnessHttp from "../src/module.ts";

const credential = randomBytes(32).toString("hex");
const now = 1_800_000_000_000;

interface Asked {
	readonly method: string;
	readonly path: string;
	readonly headers: Readonly<Record<string, string | string[] | undefined>>;
	readonly body: string;
}
interface Answer {
	readonly status: number;
	readonly json?: unknown;
	readonly text?: string;
	readonly headers?: Readonly<Record<string, string>>;
	/** Answers only after this many milliseconds. */
	readonly afterMs?: number;
}

/** A ledger keeping the witness's promises: one mark per subject, set if absent, at once. */
function keepingLedger() {
	const marks = new Map<string, string>();
	return (asked: Asked): Answer => {
		const { subject, token } = JSON.parse(asked.body);
		if (asked.path === "/w/read") return { status: 200, json: { enrolled: marks.has(subject) } };
		if (asked.path === "/w/enroll") {
			if (!marks.has(subject)) marks.set(subject, token);
			return { status: 200, json: { owner: marks.get(subject) === token } };
		}
		if (asked.path === "/w/clear") {
			marks.delete(subject);
			return { status: 204 };
		}
		return { status: 404 };
	};
}

let script: (asked: Asked) => Answer = keepingLedger();
const received: Asked[] = [];
/** A fake ledger at loopback, answering by `script`. */
function ledgerServer() {
	return createServer((req, res) => {
		let body = "";
		req.on("data", (chunk: Buffer) => {
			body += chunk;
		});
		req.on("end", () => {
			const asked = { method: req.method ?? "", path: req.url ?? "", headers: req.headers, body };
			received.push(asked);
			const answer = script(asked);
			const send = () => {
				res.writeHead(answer.status, {
					...(answer.json === undefined ? {} : { "content-type": "application/json" }),
					...answer.headers,
				});
				res.end(answer.json === undefined ? (answer.text ?? "") : JSON.stringify(answer.json));
			};
			if (answer.afterMs === undefined) send();
			else setTimeout(send, answer.afterMs);
		});
	});
}
const server = ledgerServer();
const other = ledgerServer();
const listen = (s: Server) =>
	new Promise<string>((done) =>
		s.listen(0, "127.0.0.1", () => done(`127.0.0.1:${(s.address() as AddressInfo).port}`)),
	);
let pair = "";
let otherPair = "";
beforeAll(async () => {
	pair = await listen(server);
	otherPair = await listen(other);
});
afterAll(async () => {
	server.closeAllConnections();
	other.closeAllConnections();
	await Promise.all([server, other].map((s) => new Promise<void>((done) => s.close(() => done()))));
});
beforeEach(() => {
	script = keepingLedger();
	received.length = 0;
});

const at = (path: string, where = pair) => `http://${where}${path}`;
const settings = (more: Record<string, unknown> = {}) => ({
	"read-url": at("/w/read"),
	"enroll-url": at("/w/enroll"),
	"clear-url": at("/w/clear"),
	credential,
	...more,
});
const collected = contract<readonly EnrollmentWitness[]>("test.witnesses");
const collector = defineModule({ name: "test-collector" }, (m) => [
	m.provide(collected).by((c) => c.collect(enrollmentWitnesses)),
]);
async function open(section: unknown = settings(), outbound: Record<string, unknown> = {}) {
	const logged = recordingLog();
	const app = await assemble({
		modules: [outboundModule, witnessHttp, collector],
		config: {
			...kernelConfig(),
			outbound: { allow: ["127.0.0.1"], "plain-loopback": [pair, otherPair], ...outbound },
			"mfa-witness-http": section,
		},
		runtime: quietRuntime({ log: logged.log, clock: { now: () => now } }),
	});
	const [witness] = app.get(collected);
	if (!witness) throw new Error("no witness contributed");
	return { witness, logged };
}

enrollmentWitnessContract("mfa-witness-http over a ledger keeping its promises", async () => {
	script = keepingLedger();
	return (await open()).witness;
});

describe("mfa-witness-http at a private address", () => {
	it("names the operator's URL as internal on each of its three calls, so each reaches a ledger at a private address", async () => {
		const asked: { url: string; narrower: Narrower | undefined }[] = [];
		const answers: Record<string, { status: number; body?: unknown }> = {
			"/w/read": { status: 200, body: { enrolled: false } },
			"/w/enroll": { status: 200, body: { owner: true } },
			"/w/clear": { status: 204 },
		};
		const recording = defineModule({ name: "outbound" }, (m) => [
			m.provide(outbound).by(() => ({
				fetch: async (url, _request, narrower) => {
					asked.push({ url, narrower });
					const { status, body } = answers[new URL(url).pathname] ?? { status: 404 };
					const bytes = new TextEncoder().encode(body === undefined ? "" : JSON.stringify(body));
					return { status, headers: new Map([["content-type", "application/json"]]), body: bytes };
				},
			})),
			m.provide(outboundRefusals).by(() => ({ explained: () => undefined })),
			m.provide(credentialPolicy).by(() => ({ refusalOf: () => undefined })),
			m.provide(outboundLimits).by(() => ({ of: () => ({ timeoutMs: 1000, maxBytes: 1024 }) })),
		]);
		const ledger = (path: string) => `https://ledger.corp${path}`;
		const app = await assemble({
			modules: [recording, witnessHttp, collector],
			config: {
				...kernelConfig(),
				"mfa-witness-http": settings({
					"read-url": ledger("/w/read"),
					"enroll-url": ledger("/w/enroll"),
					"clear-url": ledger("/w/clear"),
				}),
			},
			runtime: quietRuntime({ clock: { now: () => now } }),
		});
		const [witness] = app.get(collected);
		await witness?.read("alice");
		await witness?.enroll("alice", "t-1");
		await witness?.clear("alice");
		// The operator's policy, with the ledger's host among its internal hosts.
		const policy = policyOf(
			policySettings.parse({ "allow-any-public": true, "internal-hosts": ["ledger.corp"] }),
		);
		expect(asked.map(({ url }) => new URL(url).pathname)).toEqual([
			"/w/read",
			"/w/enroll",
			"/w/clear",
		]);
		for (const { url, narrower } of asked) {
			expect(policy.admit(url, narrower).internal, url).toBe(true);
		}
	});
});

describe("mfa-witness-http", () => {
	it("posts each call to its URL as written, with the credential, a write with its deadline", async () => {
		const { witness } = await open(settings({ "read-url": at("/w/read?realm=a"), timeout: "2s" }));
		script = (asked) =>
			asked.path === "/w/clear"
				? { status: 204 }
				: { status: 200, json: { enrolled: false, owner: true } };
		await witness.read("alice");
		await witness.enroll("alice", "t-1");
		await witness.clear("alice");
		expect(received.map((r) => [r.method, r.path])).toEqual([
			["POST", "/w/read?realm=a"],
			["POST", "/w/enroll"],
			["POST", "/w/clear"],
		]);
		for (const asked of received) {
			expect(asked.headers).toMatchObject({
				authorization: `Bearer ${credential}`,
				accept: "application/json",
				"content-type": "application/json",
			});
		}
		expect(received.map((r) => JSON.parse(r.body))).toEqual([
			{ subject: "alice" },
			{ subject: "alice", token: "t-1", deadline: now + 2000 },
			{ subject: "alice", deadline: now + 2000 },
		]);
	});

	it("gives a write the deadline outbound holds the call to, where outbound's timeout is the shorter", async () => {
		const { witness } = await open(settings({ timeout: "2s" }), { timeout: "500ms" });
		script = (asked) =>
			asked.path === "/w/clear" ? { status: 204 } : { status: 200, json: { owner: true } };
		await witness.enroll("alice", "t-1");
		await witness.clear("alice");
		expect(received.map((r) => JSON.parse(r.body).deadline)).toEqual([now + 500, now + 500]);
	});

	it("reads the mark and the ownership the ledger answers", async () => {
		const { witness } = await open();
		expect(await witness.read("alice")).toBe(false);
		expect(await witness.enroll("alice", "t-1")).toBe(true);
		expect(await witness.enroll("alice", "t-2")).toBe(false);
		expect(await witness.read("alice")).toBe(true);
	});

	it("leaves exactly one owner of two enrolls at once", async () => {
		const { witness } = await open();
		const raced = await Promise.all([witness.enroll("bob", "a"), witness.enroll("bob", "b")]);
		expect(raced.filter(Boolean)).toHaveLength(1);
	});

	it("passes on a ledger whose reads lag behind its answered writes, which the contract test then fails", async () => {
		const marks = new Map<string, string>();
		let seen = new Set<string>();
		script = (asked) => {
			const { subject, token } = JSON.parse(asked.body);
			if (asked.path === "/w/read") {
				// A replica a write behind: it sees what was marked before the last write.
				const answer = { status: 200, json: { enrolled: seen.has(subject) } };
				seen = new Set(marks.keys());
				return answer;
			}
			if (asked.path === "/w/enroll") {
				if (!marks.has(subject)) marks.set(subject, token);
				return { status: 200, json: { owner: marks.get(subject) === token } };
			}
			marks.delete(subject);
			return { status: 204 };
		};
		const { witness } = await open();
		expect(await witnessProblems(witness)).toContain("a read after an answered enroll misses it");
	});

	it("answers unavailable to any other answer, a 404 included, logging no value sent or answered", async () => {
		const { witness, logged } = await open();
		const calls = {
			read: () => witness.read("alice-secret"),
			enroll: () => witness.enroll("alice-secret", "token-secret"),
			clear: () => witness.clear("alice-secret"),
		};
		const answers: Record<keyof typeof calls, Answer[]> = {
			read: [
				{ status: 404 },
				{ status: 410 },
				{ status: 401 },
				{ status: 500 },
				{ status: 204 },
				{ status: 201, json: { enrolled: true } },
				{ status: 302, headers: { location: at("/w/elsewhere") } },
				{ status: 200, json: { enrolled: "true" } },
				{ status: 200, json: {} },
				{ status: 200, json: ["secret-1"] },
				{ status: 200, text: "secret-2" },
			],
			enroll: [
				{ status: 404 },
				{ status: 204 },
				{ status: 500 },
				{ status: 200, json: { owner: "yes" } },
				{ status: 200, json: { enrolled: true } },
				{ status: 200, text: "secret-3" },
			],
			clear: [{ status: 404 }, { status: 200, json: {} }, { status: 202 }, { status: 500 }],
		};
		for (const [call, list] of Object.entries(answers) as [keyof typeof calls, Answer[]][]) {
			for (const answer of list) {
				script = () => answer;
				await expect(calls[call](), `${call} ${JSON.stringify(answer)}`).rejects.toSatisfy(
					isUnavailable,
				);
			}
		}
		expect(received.map((r) => r.path).filter((p) => !p.startsWith("/w/"))).toEqual([]);
		const fields = logged.lines().map((line) => [line.event, line.fields]);
		expect(fields).toContainEqual([
			"mfa-witness-http.ledger_failed",
			{ call: "read", status: 404 },
		]);
		expect(fields).toContainEqual([
			"mfa-witness-http.ledger_failed",
			{ call: "read", reason: "redirect" },
		]);
		expect(fields).toContainEqual([
			"mfa-witness-http.ledger_failed",
			{ call: "enroll", reason: "malformed" },
		]);
		expect(fields).toContainEqual([
			"mfa-witness-http.ledger_failed",
			{ call: "clear", status: 200 },
		]);
		expect(JSON.stringify(logged.lines())).not.toContain("secret");
		expect(JSON.stringify(logged.lines())).not.toContain(credential);
	});

	it("answers unavailable to a ledger that answers past the timeout", async () => {
		const { witness, logged } = await open(settings({ timeout: "50ms" }));
		script = () => ({ status: 200, json: { enrolled: true }, afterMs: 500 });
		await expect(witness.read("alice")).rejects.toSatisfy(isUnavailable);
		expect(logged.lines().map((line) => [line.event, line.fields])).toContainEqual([
			"mfa-witness-http.ledger_failed",
			{ call: "read", reason: "timeout" },
		]);
	});

	it("refuses to start without each URL or the credential, on a URL outbound refuses, or on URLs at two origins", async () => {
		const without = (key: keyof ReturnType<typeof settings>) => {
			const { [key]: _, ...rest } = settings();
			return rest;
		};
		for (const [section, where] of [
			[without("read-url"), "mfa-witness-http.read-url"],
			[without("enroll-url"), "mfa-witness-http.enroll-url"],
			[without("clear-url"), "mfa-witness-http.clear-url"],
			[without("credential"), "mfa-witness-http.credential"],
			[settings({ credential: "short" }), "mfa-witness-http.credential"],
			[settings({ credential: `REPLACE-${"x".repeat(60)}` }), "mfa-witness-http.credential"],
			[
				settings({ "enroll-url": "https://ledger.example/w/enroll" }),
				"mfa-witness-http.enroll-url",
			],
			[settings({ "clear-url": at("/w/clear", otherPair) }), "mfa-witness-http.credential"],
		] as const) {
			const error = await open(section).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(error, JSON.stringify(section)).toBeInstanceOf(BootRefused);
			const refusals = (error as BootRefused).refusals;
			expect(refusals.map((r) => r.where)).toEqual([where]);
			expect(JSON.stringify(refusals)).not.toContain(credential);
		}
	});

	it("says why its credential may not go: its URLs' one origin in its own words, the scheme in outbound-policy's", async () => {
		const refusedFor = async (refusal: "origins" | "scheme") => {
			const standIn = defineModule({ name: "outbound" }, (m) => [
				m.provide(outbound).by(() => ({
					fetch: async () => {
						throw new Error("never sent");
					},
				})),
				m.provide(outboundRefusals).by(() => ({ explained: () => undefined })),
				m.provide(credentialPolicy).by(() => ({ refusalOf: () => refusal })),
				m.provide(outboundLimits).by(() => ({ of: () => ({ timeoutMs: 1000, maxBytes: 1024 }) })),
			]);
			const error = await assemble({
				modules: [standIn, witnessHttp, collector],
				config: { ...kernelConfig(), "mfa-witness-http": settings() },
				runtime: quietRuntime({ clock: { now: () => now } }),
			}).catch((e: unknown) => e);
			return (error as BootRefused).refusals;
		};
		expect(await refusedFor("scheme")).toEqual([
			{ where: "mfa-witness-http.credential", reason: credentialRefusalText("scheme") },
		]);
		expect(await refusedFor("origins")).toEqual([
			{
				where: "mfa-witness-http.credential",
				reason: "goes to one origin alone: read-url, enroll-url and clear-url must share it",
			},
		]);
	});

	it("says which of outbound's keys lets a URL it refuses through, naming no value", async () => {
		const error = await open(settings({ "enroll-url": "https://ledger.example/w/enroll" })).catch(
			(e: unknown) => e,
		);
		expect((error as BootRefused).refusals).toEqual([
			{
				where: "mfa-witness-http.enroll-url",
				reason:
					"outbound's destination policy refuses it: not-allowed: name the host in outbound.allow, or set outbound.allow-any-public",
			},
		]);
	});
});
