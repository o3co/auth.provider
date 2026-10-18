import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { type SignerKeys, signerKeys } from "@mod/jwt-bearer";
import jwtBearer from "@mod/jwt-bearer/module";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import storeModule from "@mod/store/module";
import { storeConfig } from "@mod/store/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { grantCaller, grantCalls } from "@mod/token-endpoint/testing";
import { tokensStandIn } from "@mod/tokens/testing";
import { SignJWT } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import signerKeysHttp from "../src/module.ts";

const credential = randomBytes(32).toString("hex");
const fixedIss = "https://devices.example";
const device = generateKeyPairSync("ed25519");
const deviceJwk = { ...device.publicKey.export({ format: "jwk" }), alg: "EdDSA" };

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
}
/** The ledger: the device's key for `dev-1`, and `dev-gone` revoked; no one else. */
function deviceLedger(asked: Asked): Answer {
	const { subject } = JSON.parse(asked.body);
	if (subject === "dev-gone") return { status: 410 };
	return subject === "dev-1" ? { status: 200, json: { keys: [deviceJwk] } } : { status: 404 };
}

let script: (asked: Asked) => Answer = deviceLedger;
const received: Asked[] = [];
const server = createServer((req, res) => {
	let body = "";
	req.on("data", (chunk: Buffer) => {
		body += chunk;
	});
	req.on("end", () => {
		const asked = { method: req.method ?? "", path: req.url ?? "", headers: req.headers, body };
		received.push(asked);
		const answer = script(asked);
		res.writeHead(answer.status, {
			...(answer.json === undefined ? {} : { "content-type": "application/json" }),
			...answer.headers,
		});
		res.end(answer.json === undefined ? (answer.text ?? "") : JSON.stringify(answer.json));
	});
});
let pair = "";
beforeAll(async () => {
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	pair = `127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((done) => server.close(() => done())));
beforeEach(() => {
	script = deviceLedger;
	received.length = 0;
});

const keysUrl = () => `http://${pair}/ledger/keys`;
const settings = (more: Record<string, unknown> = {}) => ({
	issuer: fixedIss,
	"keys-url": keysUrl(),
	credential,
	...more,
});
const collected = contract<readonly SignerKeys[]>("test.signer-keys");
const collector = defineModule({ name: "test-collector" }, (m) => [
	m.provide(collected).by((c) => c.collect(signerKeys)),
]);
async function open(section: unknown = settings(), allow = ["127.0.0.1"]) {
	const logged = recordingLog();
	const app = await assemble({
		modules: [outboundModule, signerKeysHttp, collector],
		config: {
			...kernelConfig(),
			outbound: { allow, "plain-loopback": [pair] },
			"signer-keys-http": section,
		},
		runtime: quietRuntime({ log: logged.log }),
	});
	const [keys] = app.get(collected);
	if (!keys) throw new Error("no signer keys contributed");
	return { keys, logged };
}

describe("signer-keys-http", () => {
	it("posts the issuer, the subject and the kid to keys-url as written, with the credential", async () => {
		const { keys } = await open(settings({ "keys-url": `${keysUrl()}?realm=a` }));
		expect(keys.issuer).toBe(fixedIss);
		await keys.keysOf({ subject: "dev-1", kid: "k1" });
		await keys.keysOf({ subject: "dev-1" });
		expect(received.map((r) => [r.method, r.path])).toEqual([
			["POST", "/ledger/keys?realm=a"],
			["POST", "/ledger/keys?realm=a"],
		]);
		expect(received[0]?.headers).toMatchObject({
			authorization: `Bearer ${credential}`,
			accept: "application/json",
			"content-type": "application/json",
		});
		expect(received.map((r) => JSON.parse(r.body))).toEqual([
			{ issuer: fixedIss, subject: "dev-1", kid: "k1" },
			{ issuer: fixedIss, subject: "dev-1" },
		]);
	});

	it("hands over the public keys with the grant's algorithms where none are named, asking on every call", async () => {
		const { keys } = await open();
		expect(await keys.keysOf({ subject: "dev-1" })).toEqual({
			kind: "keys",
			keys: [deviceJwk],
			algorithms: ["EdDSA", "ES256", "RS256"],
		});
		script = () => ({
			status: 200,
			json: { keys: [{ ...deviceJwk, d: "secret" }, deviceJwk], algorithms: ["EdDSA"] },
		});
		expect(await keys.keysOf({ subject: "dev-1" })).toEqual({
			kind: "keys",
			keys: [deviceJwk],
			algorithms: ["EdDSA"],
		});
		expect(received).toHaveLength(2);
	});

	it("answers none to a 404, a 410, or a 200 that names no key, unlogged", async () => {
		const { keys, logged } = await open();
		expect(await keys.keysOf({ subject: "dev-nobody" })).toEqual({ kind: "none" });
		expect(await keys.keysOf({ subject: "dev-gone" })).toEqual({ kind: "none" });
		script = () => ({ status: 200, json: { keys: [] } });
		expect(await keys.keysOf({ subject: "dev-1" })).toEqual({ kind: "none" });
		expect(logged.lines()).toEqual([]);
	});

	it("answers unavailable to anything else, a key set of private keys alone or an unknown algorithm included, logging nothing sent", async () => {
		const { keys, logged } = await open();
		const answers: Answer[] = [
			{ status: 401 },
			{ status: 403, headers: { "www-authenticate": "Bearer" } },
			{ status: 500 },
			{ status: 201, json: { keys: [deviceJwk] } },
			{ status: 302, headers: { location: `http://${pair}/ledger/elsewhere` } },
			{ status: 200, json: { keys: [{ ...deviceJwk, d: "secret-1" }] } },
			{ status: 200, json: { keys: [deviceJwk], algorithms: ["HS256"] } },
			{ status: 200, json: ["secret-2"] },
			{ status: 200, text: "secret-3" },
		];
		for (const answer of answers) {
			script = () => answer;
			await expect(keys.keysOf({ subject: "dev-1" }), JSON.stringify(answer)).rejects.toSatisfy(
				isUnavailable,
			);
		}
		expect(received.map((r) => r.path).filter((p) => p !== "/ledger/keys")).toEqual([]);
		const fields = logged.lines().map((line) => [line.event, line.fields]);
		expect(fields).toContainEqual(["signer-keys-http.ledger_failed", { status: 500 }]);
		expect(fields).toContainEqual(["signer-keys-http.ledger_failed", { reason: "malformed" }]);
		expect(JSON.stringify(logged.lines())).not.toContain("secret");
	});

	it("refuses to start without an issuer or keys-url, or on a keys-url outbound's policy refuses", async () => {
		for (const [section, where] of [
			[{ "keys-url": keysUrl() }, "signer-keys-http.issuer"],
			[{ issuer: fixedIss }, "signer-keys-http.keys-url"],
			[settings({ "keys-url": "https://ledger.example/keys" }), "signer-keys-http.keys-url"],
			[settings({ credential: "short" }), "signer-keys-http.credential"],
			[settings({ credential: `REPLACE-${"x".repeat(60)}` }), "signer-keys-http.credential"],
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
});

describe("signer-keys-http under jwt-bearer", () => {
	const issuer = "https://as.example";
	const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
	async function serve() {
		const location = defineModule({ name: "token-endpoint-location" }, (m) => [
			m.provide(tokenEndpointLocation).by(() => ({ url: `${issuer}/oauth/token` })),
		]);
		const app = await assemble({
			modules: [
				location,
				http,
				tokensStandIn(),
				issuerModule,
				clientsModule,
				grantCaller,
				clientAllowanceModule,
				outboundModule,
				externalJwtModule,
				storeModule,
				subjectRevocationStandIn,
				jwtBearer,
				signerKeysHttp,
			],
			config: {
				...kernelConfig(),
				...httpConfig(),
				...issuerConfig({ url: issuer }),
				...storeConfig(),
				outbound: { allow: ["127.0.0.1"], "plain-loopback": [pair] },
				...clientsConfig([
					confidentialClient({
						id: "app",
						sections: allowancesFor({
							grants: [grantType],
							scopes: ["read"],
							"default-scopes": ["read"],
						}),
					}),
				]),
				"jwt-bearer": { issuers: [{ issuer: fixedIss, subject: "as-is" }] },
				"signer-keys-http": settings(),
			},
			runtime: quietRuntime(),
		});
		return (assertion: string) =>
			app.get(grantCalls).call(grantType, "app", { grant_type: grantType, assertion });
	}
	const assertion = (sub: string) =>
		new SignJWT({ jti: `j-${Math.random()}`, iss: fixedIss, sub, aud: issuer })
			.setProtectedHeader({ alg: "EdDSA" })
			.setExpirationTime("2m")
			.sign(device.privateKey);

	it("issues for an assertion the ledger's key for its subject verifies, and refuses it once the device is revoked", async () => {
		const grant = await serve();
		expect((await grant(await assertion("dev-1"))).kind).toBe("issued");
		expect(await grant(await assertion("dev-gone"))).toMatchObject({
			kind: "error",
			error: "invalid_grant",
		});
	});
});
