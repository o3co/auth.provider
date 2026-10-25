import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { areaTarget, type Started, sceneOf } from "@mod/conformance";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { calculateJwkThumbprint, exportJWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, oauthArea } from "../../main.ts";

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const issuer = "https://issuer.example";
const devices = "https://devices.example";
const prefix = "device:";
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const provider = generateKeyPairSync("ed25519");
const keyOf = { alice: generateKeyPairSync("ed25519"), stranger: generateKeyPairSync("ed25519") };
type Device = keyof typeof keyOf;
const thumbOf = async (device: Device) =>
	calculateJwkThumbprint(await exportJWK(keyOf[device].publicKey), "sha256");
const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: [grantType],
	scopes: ["read"],
	defaultScopes: ["read"],
};

/** The device ledger: a device's key under its thumbprint as `kid`, for the issuer it was asked for alone. */
let ledger: Server;
const asked: unknown[] = [];
const revoked = new Set<string>();
let known: Record<string, Device> = {};
function startLedger(): Promise<string> {
	ledger = createServer((request, response) => {
		let body = "";
		request.on("data", (chunk) => {
			body += chunk;
		});
		request.on("end", () => {
			const read = JSON.parse(body || "{}") as {
				issuer?: unknown;
				subject?: unknown;
				kid?: unknown;
			};
			asked.push(read);
			const device = typeof read.subject === "string" ? known[read.subject] : undefined;
			const found = read.issuer === devices && device !== undefined && read.kid === read.subject;
			const status = !found ? 404 : revoked.has(String(read.subject)) ? 410 : 200;
			response.writeHead(status, { "content-type": "application/json" });
			const jwk = found
				? { ...keyOf[device].publicKey.export({ format: "jwk" }), kid: read.subject }
				: {};
			response.end(status === 200 ? JSON.stringify({ keys: [jwk], algorithms: ["EdDSA"] }) : "{}");
		});
	});
	return new Promise((resolve) =>
		ledger.listen(0, "127.0.0.1", () => {
			const { port } = ledger.address() as AddressInfo;
			resolve(`http://127.0.0.1:${port}/signer-keys`);
		}),
	);
}

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** An assertion a device signs: self-issued, its name its `iss` and `sub`, or under the issuer's own `iss`. */
async function assertion(device: Device, selfIssued: boolean): Promise<string> {
	const thumb = await thumbOf(device);
	const now = Math.floor(Date.now() / 1000);
	const name = selfIssued ? prefix + thumb : thumb;
	const body = {
		iss: selfIssued ? name : devices,
		sub: name,
		aud: issuer,
		iat: now,
		exp: now + 120,
		jti: `j-${Math.random()}`,
	};
	const input = `${b64({ alg: "EdDSA", typ: "JWT", kid: thumb })}.${b64(body)}`;
	return `${input}.${sign(null, Buffer.from(input), keyOf[device].privateKey).toString("base64url")}`;
}

async function grant(base: string, signed: string) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		// Through the proxy the identity part trusts, so the request has a source to count.
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.31",
		},
		body: new URLSearchParams({
			client_id: app.id,
			client_secret: app.secret ?? "",
			grant_type: grantType,
			assertion: signed,
		}),
	});
	return { status: res.status, body: (await res.json()) as Record<string, string> };
}
const subjectOf = (token = "") =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8")).sub;

describe.runIf(areaTarget().can("trusted-issuers"))(
	"C. jwt-bearer with self-issued signers",
	() => {
		let base = "";
		let running: Started;
		beforeAll(async () => {
			const alice = await thumbOf("alice");
			known = { [alice]: "alice", [await thumbOf("stranger")]: "stranger" };
			const keysUrl = await startLedger();
			running = await areaTarget().start(
				sceneOf(
					keysArea.part({
						signing: {
							kid: "js",
							alg: "EdDSA",
							privatePem: pem(provider.privateKey, "pkcs8"),
							publicPem: pem(provider.publicKey, "spki"),
						},
					}),
					identityArea.part({
						origin: issuer,
						users: [
							{
								identifier: "alice",
								password: "correct horse battery",
								subject: "user-alice",
								upstream: { idp: "devices", subject: alice },
							},
						],
					}),
					oauthArea.part({
						issuer,
						clients: [app],
						jwtBearer: {
							issuers: [
								{
									issuer: devices,
									linked: {
										upstream: "devices",
										keysUrl,
										thumbprint: true,
										selfIssuedPrefix: prefix,
									},
								},
							],
						},
					}),
				),
			);
			if (running.kind !== "running") throw new Error(running.output);
			base = running.baseUrl;
		});
		afterAll(async () => {
			if (running?.kind === "running") await running.stop();
			await new Promise((done) => ledger?.close(done));
		});

		it("issues for the user linked to a self-issued signer, asking the ledger by the issuer, the thumbprint and the kid", async () => {
			const thumb = await thumbOf("alice");
			const res = await grant(base, await assertion("alice", true));
			expect(res.status).toBe(200);
			expect(subjectOf(res.body.access_token)).toBe("user-alice");
			expect(asked.at(-1)).toEqual({ issuer: devices, subject: thumb, kid: thumb });
		});

		it("takes the same key under the issuer's own iss as the same user", async () => {
			const res = await grant(base, await assertion("alice", false));
			expect(res.status).toBe(200);
			expect(subjectOf(res.body.access_token)).toBe("user-alice");
		});

		it("refuses a self-issued signer no user is linked to, and one the ledger does not know", async () => {
			const unlinked = await grant(base, await assertion("stranger", true));
			expect([unlinked.status, unlinked.body.error]).toEqual([400, "invalid_grant"]);
			known = { [await thumbOf("alice")]: "alice" };
			const unknown = await grant(base, await assertion("stranger", true));
			expect([unknown.status, unknown.body.error]).toEqual([400, "invalid_grant"]);
		});

		it("refuses a self-issued signer the ledger revoked since its last assertion", async () => {
			const thumb = await thumbOf("alice");
			expect((await grant(base, await assertion("alice", true))).status).toBe(200);
			revoked.add(thumb);
			const res = await grant(base, await assertion("alice", true));
			expect([res.status, res.body.error]).toEqual([400, "invalid_grant"]);
			revoked.delete(thumb);
		});
	},
);
