import { generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, oauthScene } from "../../main.ts";

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const issuer = "https://issuer.example";
const ledgered = "https://devices.example";
const unledgered = "https://idp.example";
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const provider = generateKeyPairSync("ed25519");
const devices = generateKeyPairSync("ed25519");
const idp = generateKeyPairSync("ed25519");
const token = randomBytes(32).toString("hex");
const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: [grantType],
	scopes: ["read"],
	defaultScopes: ["read"],
};

/**
 * The ledger as deployed, shared with another service: `POST` with the token in X-Internal-Token
 * and `{jti, exp}`; 204 the first time, 409 after, 400 for a malformed body, 401 for another
 * token, 503 while its store is out. `mode` makes it fail as a deployment's may.
 */
let ledger: Server;
const consumed = new Map<string, number>();
const seen: { jti: unknown; exp: unknown; token: unknown; authorization: unknown }[] = [];
let mode: "up" | "down" | "lose-next" = "up";
/** Uses a jti up as the other service does: the ledger's own answer. */
function consume(jti: unknown, exp: unknown): number {
	if (typeof jti !== "string" || jti === "" || jti.length > 256) return 400;
	if (typeof exp !== "number" || exp <= 0) return 400;
	if (consumed.has(jti)) return 409;
	consumed.set(jti, exp);
	return 204;
}
function startLedger(): Promise<string> {
	ledger = createServer((request, response) => {
		let body = "";
		request.on("data", (chunk) => {
			body += chunk;
		});
		request.on("end", () => {
			const sent = JSON.parse(body || "{}") as { jti?: unknown; exp?: unknown };
			const given = request.headers["x-internal-token"];
			seen.push({
				jti: sent.jti,
				exp: sent.exp,
				token: given,
				authorization: request.headers.authorization,
			});
			if (mode === "down") return void response.writeHead(503).end();
			if (given !== token) return void response.writeHead(401).end();
			const status = consume(sent.jti, sent.exp);
			if (mode === "lose-next") {
				mode = "up";
				return void request.socket.destroy();
			}
			response.writeHead(status).end();
		});
	});
	return new Promise((resolve) =>
		ledger.listen(0, "127.0.0.1", () => {
			const { port } = ledger.address() as AddressInfo;
			resolve(`http://127.0.0.1:${port}/assertions/consume`);
		}),
	);
}

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** An assertion `key` signs for `from`, its jti `jti`. */
function assertion(from: string, key: KeyObject, jti = `j-${Math.random()}`): string {
	const now = Math.floor(Date.now() / 1000);
	const body = { iss: from, sub: "alice", aud: issuer, iat: now, exp: now + 120, jti };
	const input = `${b64({ alg: "EdDSA", typ: "JWT" })}.${b64(body)}`;
	return `${input}.${sign(null, Buffer.from(input), key).toString("base64url")}`;
}

async function grant(base: string, signed: string) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			client_id: app.id,
			client_secret: app.secret ?? "",
			grant_type: grantType,
			assertion: signed,
		}),
	});
	return { status: res.status, body: (await res.json()) as Record<string, string> };
}
const outcome = (res: { status: number; body: Record<string, string> }) =>
	res.status === 200 ? "issued" : `${res.status} ${res.body.error}`;

describe.runIf(areaTarget().can("trusted-issuers"))(
	"C. jwt-bearer using jtis up in a shared ledger",
	() => {
		let base = "";
		let running: Started;
		beforeAll(async () => {
			const consumeUrl = await startLedger();
			running = await areaTarget().start(
				oauthScene({
					issuer,
					keys: {
						signing: {
							kid: "jl",
							alg: "EdDSA",
							privatePem: pem(provider.privateKey, "pkcs8"),
							publicPem: pem(provider.publicKey, "spki"),
						},
					},
					clients: [app],
					jwtBearer: {
						issuers: [
							{
								issuer: ledgered,
								alg: "EdDSA",
								publicPem: pem(devices.publicKey, "spki"),
								jtiLedger: { consumeUrl, credential: token, credentialHeader: "x-internal-token" },
							},
							{ issuer: unledgered, alg: "EdDSA", publicPem: pem(idp.publicKey, "spki") },
						],
					},
				}),
			);
			if (running.kind !== "running") throw new Error(running.output);
			base = running.baseUrl;
		});
		afterAll(async () => {
			if (running?.kind === "running") await running.stop();
			await new Promise((done) => ledger?.close(done));
		});

		it("uses the jti up in the ledger on its wire, so the other service refuses it after", async () => {
			const jti = `j-${Math.random()}`;
			expect(outcome(await grant(base, assertion(ledgered, devices.privateKey, jti)))).toBe(
				"issued",
			);
			const [asked] = seen.filter((s) => s.jti === jti);
			expect(asked).toMatchObject({ token, authorization: undefined });
			expect(typeof asked?.exp === "number" && Number.isInteger(asked.exp)).toBe(true);
			expect(consume(jti, 1)).toBe(409);
		});

		it("refuses an assertion the other service used up first", async () => {
			const jti = `j-${Math.random()}`;
			expect(consume(jti, Math.floor(Date.now() / 1000) + 120)).toBe(204);
			expect(outcome(await grant(base, assertion(ledgered, devices.privateKey, jti)))).toBe(
				"400 invalid_grant",
			);
		});

		it("lets one of the other service and the grant use one jti at once", async () => {
			const jti = `j-${Math.random()}`;
			const [granted, other] = await Promise.all([
				grant(base, assertion(ledgered, devices.privateKey, jti)),
				Promise.resolve().then(() => consume(jti, Math.floor(Date.now() / 1000) + 120)),
			]);
			expect([outcome(granted) === "issued", other === 204].filter(Boolean)).toHaveLength(1);
		});

		it("answers 503 while the ledger is out, uses nothing up elsewhere, and issues once it is back", async () => {
			const signed = assertion(ledgered, devices.privateKey);
			mode = "down";
			try {
				expect(outcome(await grant(base, signed))).toBe("503 temporarily_unavailable");
			} finally {
				mode = "up";
			}
			// No store took it meanwhile: the ledger, back, sees it first.
			expect(outcome(await grant(base, signed))).toBe("issued");
		});

		it("answers 503 to a lost answer, the assertion then used up", async () => {
			const signed = assertion(ledgered, devices.privateKey);
			mode = "lose-next";
			expect(outcome(await grant(base, signed))).toBe("503 temporarily_unavailable");
			expect(outcome(await grant(base, signed))).toBe("400 invalid_grant");
		});

		it("keeps an issuer without a ledger on the store, asking the ledger nothing", async () => {
			const before = seen.length;
			const signed = assertion(unledgered, idp.privateKey);
			expect(outcome(await grant(base, signed))).toBe("issued");
			expect(outcome(await grant(base, signed))).toBe("400 invalid_grant");
			expect(seen.length).toBe(before);
		});
	},
);
