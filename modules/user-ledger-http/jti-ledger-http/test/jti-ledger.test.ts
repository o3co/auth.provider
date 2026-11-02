import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { type JtiLedger, jtiLedgers } from "@mod/jwt-bearer";
import { jtiLedgerContract } from "@mod/jwt-bearer/testing";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import jtiLedgerHttp from "../src/module.ts";

const credential = randomBytes(32).toString("hex");
const fixedIss = "https://devices.example";

interface Asked {
	readonly method: string;
	readonly path: string;
	readonly headers: IncomingMessage["headers"];
	readonly body: string;
}
/** How the ledger answers a consume: a status, a body, or the connection dropped once it recorded. */
type Answer = {
	readonly status: number;
	readonly text?: string;
	readonly drop?: boolean;
	readonly delayMs?: number;
};

/** The ledger as deployed: a jti once, kept until its exp by its own clock; 204, then 409. */
function ledgerAnswer(used: Map<string, number>, now: () => number) {
	return (asked: Asked): Answer => {
		const { jti, exp } = JSON.parse(asked.body) as { jti: string; exp: number };
		const until = used.get(jti);
		if (until !== undefined && now() < until * 1000) return { status: 409 };
		used.set(jti, exp);
		return { status: 204 };
	};
}

let ledgerNow = 0;
const used = new Map<string, number>();
let script: (asked: Asked) => Answer = ledgerAnswer(used, () => ledgerNow);
const received: Asked[] = [];
const server = createServer((req: IncomingMessage, res: ServerResponse) => {
	let body = "";
	req.on("data", (chunk: Buffer) => {
		body += chunk;
	});
	req.on("end", () => {
		const asked = { method: req.method ?? "", path: req.url ?? "", headers: req.headers, body };
		received.push(asked);
		const answer = script(asked);
		const respond = () => {
			if (answer.drop) return void req.socket.destroy();
			res.writeHead(answer.status);
			res.end(answer.text ?? "");
		};
		if (answer.delayMs) setTimeout(respond, answer.delayMs);
		else respond();
	});
});
let pair = "";
beforeAll(async () => {
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	pair = `127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((done) => server.close(() => done())));
beforeEach(() => {
	used.clear();
	ledgerNow = 0;
	script = ledgerAnswer(used, () => ledgerNow);
	received.length = 0;
});

const consumeUrl = () => `http://${pair}/assertions/consume`;
const settings = (more: Record<string, unknown> = {}) => ({
	issuer: fixedIss,
	"consume-url": consumeUrl(),
	credential,
	"credential-header": "x-internal-token",
	...more,
});
const collected = contract<readonly JtiLedger[]>("test.jti-ledgers");
const collector = defineModule(
	{ name: "test-collector", replicaSafe: false, takes: [jtiLedgers] },
	(m) => [m.provide(collected).by((c) => c.collect(jtiLedgers))],
);
async function open(section: unknown = settings()) {
	const logged = recordingLog();
	const app = await assemble({
		modules: [outboundModule, tlsOptionsForTests, jtiLedgerHttp, collector],
		config: {
			...kernelConfig(),
			outbound: { allow: ["127.0.0.1"], "plain-loopback": [pair] },
			"jti-ledger-http": section,
		},
		runtime: quietRuntime({ log: logged.log }),
	});
	const [ledger] = app.get(collected);
	if (!ledger) throw new Error("no ledger contributed");
	// What the ledger logs once booted: outbound's start warnings (its plain-loopback pair) come before.
	const from = logged.lines().length;
	return { ledger, logged: { lines: () => logged.lines().slice(from) } };
}
const spending = (jti: string, keepUntil = 1_800_000_090_500) => ({
	sentIssuer: fixedIss,
	jti,
	expiresAt: keepUntil - 90_000,
	keepUntil,
});

describe("jti-ledger-http", () => {
	it("posts the jti and when it may be forgotten to consume-url as written, the token in the header named", async () => {
		const { ledger } = await open(settings({ "consume-url": `${consumeUrl()}?realm=a` }));
		expect(ledger.issuer).toBe(fixedIss);
		expect(await ledger.spend(spending("j-1"))).toBe("first");
		expect(received.map((r) => [r.method, r.path])).toEqual([
			["POST", "/assertions/consume?realm=a"],
		]);
		const [asked] = received;
		expect(asked?.headers).toMatchObject({
			"x-internal-token": credential,
			accept: "application/json",
			"content-type": "application/json",
		});
		expect(asked?.headers.authorization).toBeUndefined();
		// Exactly the ledger's two members: the jti as sent, and keepUntil in whole seconds, rounded up.
		expect(asked?.body).toBe(JSON.stringify({ jti: "j-1", exp: 1_800_000_091 }));
	});

	it("sends its credential as a bearer Authorization where no header is named, and none without one", async () => {
		const { ledger } = await open(settings({ "credential-header": undefined }));
		await ledger.spend(spending("j-2"));
		expect(received.at(-1)?.headers.authorization).toBe(`Bearer ${credential}`);
		const bare = await open({ issuer: fixedIss, "consume-url": consumeUrl() });
		await bare.ledger.spend(spending("j-3"));
		expect(received.at(-1)?.headers.authorization).toBeUndefined();
		expect(received.at(-1)?.headers["x-internal-token"]).toBeUndefined();
	});

	it("reads 204 as first and 409 as replayed, by the status alone, unlogged", async () => {
		const { ledger, logged } = await open();
		expect(await ledger.spend(spending("j-4"))).toBe("first");
		expect(await ledger.spend(spending("j-4"))).toBe("replayed");
		script = () => ({ status: 409, text: "secret-said" });
		expect(await ledger.spend(spending("j-5"))).toBe("replayed");
		expect(logged.lines()).toEqual([]);
	});

	it("answers unavailable to any other status, a 200 or a 201 too, and to a lost answer, telling no jti, credential or body", async () => {
		const { ledger, logged } = await open();
		for (const answer of [
			{ status: 200, text: "secret-said" },
			{ status: 201 },
			{ status: 400 },
			{ status: 401 },
			{ status: 503 },
			{ status: 500 },
			{ status: 302 },
			{ status: 204, drop: true },
		]) {
			script = () => answer;
			await expect(ledger.spend(spending("j-secret")), JSON.stringify(answer)).rejects.toSatisfy(
				isUnavailable,
			);
		}
		const fields = logged.lines().map((line) => [line.event, line.fields]);
		expect(fields).toContainEqual(["jti-ledger-http.ledger_failed", { status: 401 }]);
		expect(fields).toContainEqual(["jti-ledger-http.ledger_failed", { status: 200 }]);
		expect(fields.every(([event]) => event === "jti-ledger-http.ledger_failed")).toBe(true);
		const told = JSON.stringify(logged.lines());
		for (const hidden of ["j-secret", credential, "secret-said"])
			expect(told).not.toContain(hidden);
	});

	it("answers unavailable to an answer past its time or its size, telling its kind alone", async () => {
		const slow = await open(settings({ timeout: "50ms" }));
		script = () => ({ status: 204, delayMs: 500 });
		await expect(slow.ledger.spend(spending("j-slow"))).rejects.toSatisfy(isUnavailable);
		const small = await open(settings({ "max-response-size": "8B" }));
		script = () => ({ status: 409, text: "x".repeat(64) });
		await expect(small.ledger.spend(spending("j-big"))).rejects.toSatisfy(isUnavailable);
		const told = [...slow.logged.lines(), ...small.logged.lines()].map((l) => [l.event, l.fields]);
		expect(told).toEqual([
			["jti-ledger-http.ledger_failed", { reason: "timeout" }],
			["jti-ledger-http.ledger_failed", { reason: "too-large" }],
		]);
	});

	it("sends no jti over the ledger's 256 bytes, however few its characters, answering unavailable", async () => {
		const { ledger, logged } = await open();
		expect(await ledger.spend(spending("é".repeat(128)))).toBe("first");
		const long = "é".repeat(129);
		await expect(ledger.spend(spending(long))).rejects.toSatisfy(isUnavailable);
		expect(received).toHaveLength(1);
		expect(logged.lines().map((line) => [line.event, line.fields])).toEqual([
			["jti-ledger-http.ledger_failed", { reason: "jti-too-long" }],
		]);
	});

	it("refuses to start without an issuer or consume-url, on one outbound's policy refuses, or on a credential or its header it may not send", async () => {
		for (const [section, where] of [
			[{ "consume-url": consumeUrl() }, "jti-ledger-http.issuer"],
			[{ issuer: fixedIss }, "jti-ledger-http.consume-url"],
			[
				settings({ "consume-url": "https://ledger.example/consume" }),
				"jti-ledger-http.consume-url",
			],
			[settings({ credential: "short" }), "jti-ledger-http.credential"],
			[settings({ "credential-header": "host" }), "jti-ledger-http.credential-header"],
			[settings({ "credential-header": "Content-Length" }), "jti-ledger-http.credential-header"],
			[settings({ "credential-header": "x token" }), "jti-ledger-http.credential-header"],
			[settings({ credential: undefined }), "jti-ledger-http.credential-header"],
		] as const) {
			const error = await open(section).then(
				() => undefined,
				(e: unknown) => e,
			);
			expect(error, JSON.stringify(section)).toBeInstanceOf(BootRefused);
			const refusals = (error as BootRefused).refusals;
			expect(
				refusals.map((r) => r.where),
				JSON.stringify(section),
			).toEqual([where]);
			expect(JSON.stringify(refusals)).not.toContain(credential);
		}
	});
});

it("takes all it names", async () => {
	const unused = await takesUnused({
		modules: [outboundModule, tlsOptionsForTests, jtiLedgerHttp, collector],
		config: {
			...kernelConfig(),
			"jti-ledger-http": settings({ "consume-url": "https://ledger.example/c" }),
			outbound: { allow: ["ledger.example"] },
		},
		runtime: quietRuntime(),
	});
	expect(unused["jti-ledger-http"]).toBeUndefined();
});

jtiLedgerContract("jti-ledger-http over the ledger's wire", async () => {
	const { ledger } = await open();
	let lose = false;
	const answer = ledgerAnswer(used, () => ledgerNow);
	script = (asked) => {
		const told = answer(asked);
		if (!lose) return told;
		lose = false;
		return { ...told, drop: true };
	};
	return {
		ledger,
		advance: (ms) => {
			ledgerNow += ms;
		},
		loseNextAnswer: () => {
			lose = true;
		},
	};
});
