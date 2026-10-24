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
import { type PasskeyWitness, passkeyWitnesses } from "@mod/passkeys";
import { passkeyWitnessContract, passkeyWitnessProblems } from "@mod/passkeys/testing";
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

/** A ledger keeping the witness's promises: one mark per subject, set if absent, at once, read with its token. */
function keepingLedger() {
	const marks = new Map<string, string>();
	return (asked: Asked): Answer => {
		const { subject, token } = JSON.parse(asked.body);
		if (asked.path === "/w/read") {
			const held = marks.get(subject);
			return {
				status: 200,
				json: held === undefined ? { enrolled: false } : { enrolled: true, token: held },
			};
		}
		if (asked.path === "/w/enroll") {
			if (!marks.has(subject)) marks.set(subject, token);
			return { status: 200, json: { owner: marks.get(subject) === token } };
		}
		if (asked.path === "/w/withdraw") {
			if (marks.get(subject) === token) marks.delete(subject);
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
	"withdraw-url": at("/w/withdraw"),
	credential,
	...more,
});
const collected = contract<readonly PasskeyWitness[]>("test.witnesses");
const collector = defineModule({ name: "test-collector" }, (m) => [
	m.provide(collected).by((c) => c.collect(passkeyWitnesses)),
]);
async function open(section: unknown = settings(), outbound: Record<string, unknown> = {}) {
	const logged = recordingLog();
	const app = await assemble({
		modules: [outboundModule, witnessHttp, collector],
		config: {
			...kernelConfig(),
			outbound: { allow: ["127.0.0.1"], "plain-loopback": [pair, otherPair], ...outbound },
			"passkey-witness-http": section,
		},
		runtime: quietRuntime({ log: logged.log, clock: { now: () => now } }),
	});
	const [witness] = app.get(collected);
	if (!witness) throw new Error("no witness contributed");
	return { witness, logged };
}

passkeyWitnessContract("passkey-witness-http over a ledger keeping its promises", async () => {
	script = keepingLedger();
	return (await open()).witness;
});

describe("passkey-witness-http's markedWith", () => {
	it("reads the mark's token from the read answer, none where unmarked, asking the read URL once a call", async () => {
		const { witness } = await open();
		expect(await witness.markedWith?.("alice")).toBeUndefined();
		await witness.enroll("alice", "t-1");
		await witness.enroll("alice", "t-2");
		expect(await witness.markedWith?.("alice")).toBe("t-1");
		const reads = received.filter((r) => r.path === "/w/read").map((r) => JSON.parse(r.body));
		expect(reads).toEqual([{ subject: "alice" }, { subject: "alice" }]);
	});

	it("answers unavailable where a marked answer names no token, for read and markedWith alike, never withdrawing or clearing instead", async () => {
		const { witness, logged } = await open();
		for (const json of [
			{ enrolled: true },
			{ enrolled: true, token: "" },
			{ enrolled: true, token: 5 },
		]) {
			script = (asked) => (asked.path === "/w/read" ? { status: 200, json } : { status: 204 });
			await expect(witness.markedWith?.("alice-secret"), JSON.stringify(json)).rejects.toSatisfy(
				isUnavailable,
			);
			await expect(witness.read("alice-secret"), JSON.stringify(json)).rejects.toSatisfy(
				isUnavailable,
			);
		}
		expect(received.map((r) => r.path).every((path) => path === "/w/read")).toBe(true);
		const failures = logged
			.lines()
			.filter((line) => line.event === "passkey-witness-http.ledger_failed")
			.map((line) => line.fields);
		expect(failures).toEqual(Array(6).fill({ call: "read", reason: "malformed" }));
		expect(JSON.stringify(logged.lines())).not.toContain("alice-secret");
	});

	it("answers unavailable to a read whose token makes it larger than max-response-size, for read and markedWith alike", async () => {
		const { witness, logged } = await open(settings({ "max-response-size": "64B" }));
		const token = "t".repeat(200);
		script = () => ({ status: 200, json: { enrolled: true, token } });
		await expect(witness.read("alice")).rejects.toSatisfy(isUnavailable);
		await expect(witness.markedWith?.("alice")).rejects.toSatisfy(isUnavailable);
		const failures = logged
			.lines()
			.filter((line) => line.event === "passkey-witness-http.ledger_failed")
			.map((line) => line.fields);
		expect(failures).toEqual(Array(2).fill({ call: "read", reason: "too-large" }));
		expect(JSON.stringify(logged.lines())).not.toContain(token);
	});

	it("reads an unmarked answer as no token, whatever else it names", async () => {
		const { witness } = await open();
		script = () => ({ status: 200, json: { enrolled: false, token: "stale" } });
		expect(await witness.markedWith?.("alice")).toBeUndefined();
		expect(await witness.read("alice")).toBe(false);
	});
});

describe("passkey-witness-http at a private address", () => {
	it("names the operator's URL as internal on each of its three calls, so each reaches a ledger at a private address", async () => {
		const asked: { url: string; narrower: Narrower | undefined }[] = [];
		const answers: Record<string, { status: number; body?: unknown }> = {
			"/w/read": { status: 200, body: { enrolled: false } },
			"/w/enroll": { status: 200, body: { owner: true } },
			"/w/withdraw": { status: 204 },
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
				"passkey-witness-http": settings({
					"read-url": ledger("/w/read"),
					"enroll-url": ledger("/w/enroll"),
					"withdraw-url": ledger("/w/withdraw"),
				}),
			},
			runtime: quietRuntime({ clock: { now: () => now } }),
		});
		const [witness] = app.get(collected);
		await witness?.read("alice");
		await witness?.enroll("alice", "t-1");
		await witness?.withdraw("alice", "t-1");
		// The operator's policy, with the ledger's host among its internal hosts.
		const policy = policyOf(
			policySettings.parse({ "allow-any-public": true, "internal-hosts": ["ledger.corp"] }),
		);
		expect(asked.map(({ url }) => new URL(url).pathname)).toEqual([
			"/w/read",
			"/w/enroll",
			"/w/withdraw",
		]);
		for (const { url, narrower } of asked) {
			expect(policy.admit(url, narrower).internal, url).toBe(true);
		}
	});
});

describe("passkey-witness-http", () => {
	it("posts each call to its URL as written, with the credential, a write with its deadline", async () => {
		const { witness } = await open(settings({ "read-url": at("/w/read?realm=a"), timeout: "2s" }));
		script = (asked) =>
			asked.path === "/w/withdraw"
				? { status: 204 }
				: { status: 200, json: { enrolled: false, owner: true } };
		await witness.read("alice");
		await witness.enroll("alice", "t-1");
		await witness.withdraw("alice", "t-1");
		expect(received.map((r) => [r.method, r.path])).toEqual([
			["POST", "/w/read?realm=a"],
			["POST", "/w/enroll"],
			["POST", "/w/withdraw"],
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
			{ subject: "alice", token: "t-1", deadline: now + 2000 },
		]);
	});

	it("gives a write the deadline outbound holds the call to, where outbound's timeout is the shorter", async () => {
		const { witness } = await open(settings({ timeout: "2s" }), { timeout: "500ms" });
		script = (asked) =>
			asked.path === "/w/enroll" ? { status: 200, json: { owner: true } } : { status: 204 };
		await witness.enroll("alice", "t-1");
		await witness.withdraw("alice", "t-1");
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
		let seen = new Map<string, string>();
		script = (asked) => {
			const { subject, token } = JSON.parse(asked.body);
			if (asked.path === "/w/read") {
				// A replica a write behind: it sees what was marked before the last write.
				const behind = seen.get(subject);
				const answer = {
					status: 200,
					json: behind === undefined ? { enrolled: false } : { enrolled: true, token: behind },
				};
				seen = new Map(marks);
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
		expect(await passkeyWitnessProblems(witness)).toContain(
			"a read after an answered enroll misses it",
		);
	});

	it("answers unavailable to any other answer, a 404 included, logging no value sent or answered", async () => {
		const { witness, logged } = await open();
		const calls = {
			read: () => witness.read("alice-secret"),
			enroll: () => witness.enroll("alice-secret", "token-secret"),
			withdraw: () => witness.withdraw("alice-secret", "token-secret"),
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
			withdraw: [{ status: 404 }, { status: 200, json: {} }, { status: 202 }, { status: 500 }],
		};
		for (const [call, list] of Object.entries(answers) as [keyof typeof calls, Answer[]][]) {
			for (const answer of list) {
				script = () => answer;
				const before = received.length;
				await expect(calls[call](), `${call} ${JSON.stringify(answer)}`).rejects.toSatisfy(
					isUnavailable,
				);
				// Each call asks its own URL once: a failed withdraw never falls back to the clear.
				expect(
					received.slice(before).map((r) => r.path),
					`${call} ${JSON.stringify(answer)}`,
				).toEqual([`/w/${call}`]);
			}
		}
		expect(received.map((r) => r.path).filter((p) => !p.startsWith("/w/"))).toEqual([]);
		const fields = logged.lines().map((line) => [line.event, line.fields]);
		expect(fields).toContainEqual([
			"passkey-witness-http.ledger_failed",
			{ call: "read", status: 404 },
		]);
		expect(fields).toContainEqual([
			"passkey-witness-http.ledger_failed",
			{ call: "read", reason: "redirect" },
		]);
		expect(fields).toContainEqual([
			"passkey-witness-http.ledger_failed",
			{ call: "enroll", reason: "malformed" },
		]);
		expect(fields).toContainEqual([
			"passkey-witness-http.ledger_failed",
			{ call: "withdraw", status: 200 },
		]);
		expect(JSON.stringify(logged.lines())).not.toContain("secret");
		expect(JSON.stringify(logged.lines())).not.toContain(credential);
	});

	it("answers unavailable to a ledger that answers past the timeout", async () => {
		const { witness, logged } = await open(settings({ timeout: "50ms" }));
		script = () => ({ status: 200, json: { enrolled: true }, afterMs: 500 });
		await expect(witness.read("alice")).rejects.toSatisfy(isUnavailable);
		expect(logged.lines().map((line) => [line.event, line.fields])).toContainEqual([
			"passkey-witness-http.ledger_failed",
			{ call: "read", reason: "timeout" },
		]);
	});

	it("refuses to start without each URL or the credential, on a URL outbound refuses, or on URLs at two origins", async () => {
		const without = (key: keyof ReturnType<typeof settings>) => {
			const { [key]: _, ...rest } = settings();
			return rest;
		};
		for (const [section, where] of [
			[without("read-url"), "passkey-witness-http.read-url"],
			[without("enroll-url"), "passkey-witness-http.enroll-url"],
			[without("withdraw-url"), "passkey-witness-http.withdraw-url"],
			[without("credential"), "passkey-witness-http.credential"],
			[settings({ credential: "short" }), "passkey-witness-http.credential"],
			[settings({ credential: `REPLACE-${"x".repeat(60)}` }), "passkey-witness-http.credential"],
			[
				settings({ "enroll-url": "https://ledger.example/w/enroll" }),
				"passkey-witness-http.enroll-url",
			],
			[
				settings({ "withdraw-url": at("/w/withdraw", otherPair) }),
				"passkey-witness-http.credential",
			],
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

	it("offers no clear, and refuses to start on a clear-url still written, naming the key and never a value", async () => {
		const { witness } = await open();
		expect("clear" in witness).toBe(false);
		const error = await open(settings({ "clear-url": at("/w/clear-secret") })).catch(
			(e: unknown) => e,
		);
		expect(error).toBeInstanceOf(BootRefused);
		const refusals = (error as BootRefused).refusals;
		expect(refusals.map((r) => r.where)).toEqual(["passkey-witness-http"]);
		expect(JSON.stringify(refusals)).toContain("clear-url");
		expect(JSON.stringify(refusals)).not.toContain("clear-secret");
	});

	it("takes a withdraw-url at any path of the ledger's origin, the old clear path included", async () => {
		for (const withdraw of [at("/w/withdraw"), at("/w/clear"), `${at("/w/clear")}?only=token`]) {
			expect((await open(settings({ "withdraw-url": withdraw }))).witness, withdraw).toBeDefined();
		}
	});

	it("says why its credential may not go in outbound-policy's words, for the scheme and for its URLs' one origin", async () => {
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
				config: { ...kernelConfig(), "passkey-witness-http": settings() },
				runtime: quietRuntime({ clock: { now: () => now } }),
			}).catch((e: unknown) => e);
			return (error as BootRefused).refusals;
		};
		for (const refusal of ["scheme", "origins"] as const) {
			expect(await refusedFor(refusal), refusal).toEqual([
				{ where: "passkey-witness-http.credential", reason: credentialRefusalText(refusal) },
			]);
		}
	});

	it("says which of outbound's keys lets a URL it refuses through, naming no value", async () => {
		const error = await open(settings({ "enroll-url": "https://ledger.example/w/enroll" })).catch(
			(e: unknown) => e,
		);
		expect((error as BootRefused).refusals).toEqual([
			{
				where: "passkey-witness-http.enroll-url",
				reason:
					"outbound's destination policy refuses it: not-allowed: name the host in outbound.allow, or set outbound.allow-any-public",
			},
		]);
	});
});
