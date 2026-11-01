import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { areaTarget, type Started, sceneOf } from "@mod/conformance";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, oauthArea } from "../../main.ts";

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const issuer = "https://issuer.example";
const devices = "https://devices.example";
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const provider = generateKeyPairSync("ed25519");
/** Each device's key, by its handle: the `sub` its assertions carry. */
const deviceKeys = {
	"device-alice": generateKeyPairSync("ed25519"),
	"device-unlinked": generateKeyPairSync("ed25519"),
	"device-revoked": generateKeyPairSync("ed25519"),
};
type Handle = keyof typeof deviceKeys;
const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: [grantType],
	scopes: ["read"],
	defaultScopes: ["read"],
};

/** The device ledger: a device's public key by its handle, for its issuer and no kid alone; 410 once revoked, 404 when not known. */
let ledger: Server;
const asked: { issuer?: unknown; subject?: unknown; kid?: unknown }[] = [];
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
			const { issuer: named, subject, kid } = read;
			asked.push(read);
			// Its devices name no kid: one asked for another issuer, or by a kid, is none it knows.
			const known =
				named === devices &&
				kid === undefined &&
				typeof subject === "string" &&
				subject in deviceKeys;
			const status = !known ? 404 : subject === "device-revoked" ? 410 : 200;
			response.writeHead(status, { "content-type": "application/json" });
			const jwk = known ? deviceKeys[subject as Handle].publicKey.export({ format: "jwk" }) : {};
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
/** An assertion a device signs, naming its handle as `sub`. */
function assertion(handle: Handle): string {
	const now = Math.floor(Date.now() / 1000);
	const body = {
		iss: devices,
		sub: handle,
		aud: issuer,
		iat: now,
		exp: now + 120,
		jti: `j-${Math.random()}`,
	};
	const input = `${b64({ alg: "EdDSA", typ: "JWT" })}.${b64(body)}`;
	return `${input}.${sign(null, Buffer.from(input), deviceKeys[handle].privateKey).toString("base64url")}`;
}

async function grant(base: string, handle: Handle) {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		// Through the proxy the identity part trusts, so the request has a source to count.
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.30",
		},
		body: new URLSearchParams({
			client_id: app.id,
			client_secret: app.secret ?? "",
			grant_type: grantType,
			assertion: assertion(handle),
		}),
	});
	return { status: res.status, body: (await res.json()) as Record<string, string> };
}

describe.runIf(areaTarget().can("trusted-issuers"))("C. jwt-bearer with a linked issuer", () => {
	let base = "";
	let running: Started;
	beforeAll(async () => {
		const keysUrl = await startLedger();
		running = await areaTarget().start(
			sceneOf(
				keysArea.part({
					signing: {
						kid: "jl",
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
							upstream: { idp: "devices", subject: "device-alice" },
						},
					],
				}),
				oauthArea.part({
					issuer,
					clients: [app],
					jwtBearer: { issuers: [{ issuer: devices, linked: { upstream: "devices", keysUrl } }] },
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

	it("issues a token for the user linked to the device that signed, its key asked of the ledger", async () => {
		const res = await grant(base, "device-alice");
		expect(res.status).toBe(200);
		const [, payload = ""] = (res.body.access_token ?? "").split(".");
		expect(JSON.parse(Buffer.from(payload, "base64url").toString("utf8")).sub).toBe("user-alice");
		expect(asked.at(-1)).toEqual({ issuer: devices, subject: "device-alice" });
	});

	it("refuses a device no user is linked to", async () => {
		const res = await grant(base, "device-unlinked");
		expect([res.status, res.body.error]).toEqual([400, "invalid_grant"]);
	});

	it("refuses a device the ledger says is revoked", async () => {
		const res = await grant(base, "device-revoked");
		expect([res.status, res.body.error]).toEqual([400, "invalid_grant"]);
	});
});
