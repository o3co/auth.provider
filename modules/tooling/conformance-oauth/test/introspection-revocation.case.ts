import { generateKeyPairSync } from "node:crypto";
import { areaTarget, auditEvents, faultyTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, oauthScene } from "../src/main.ts";

const pair = generateKeyPairSync("ed25519");
const secretOf = (id: string) => `${id}-secret-0123456789abcdef`;
const confidential = (id: string, audiences: string[], grants: string[] = []): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: secretOf(id),
	grants,
	scopes: ["read"],
	defaultScopes: ["read"],
	audiences,
});
const scene = oauthScene({
	issuer: "https://issuer.example",
	keys: {
		signing: {
			kid: "tc",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		confidential("app", ["https://api.example"], ["client_credentials"]),
		confidential("other", ["https://api.example"], ["client_credentials"]),
		confidential("resource", ["https://api.example"]),
		confidential("stranger", ["https://elsewhere.example"]),
		{ id: "pub", kind: "public", method: "none", grants: [], scopes: [] },
	],
	introspection: true,
	revocation: true,
});

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

async function post(path: string, form: Record<string, string>) {
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams(form),
	});
	const text = await res.text();
	return {
		status: res.status,
		headers: res.headers,
		body: (text ? JSON.parse(text) : {}) as Record<string, unknown>,
	};
}
const as = (id: string) =>
	id === "pub" ? { client_id: id } : { client_id: id, client_secret: secretOf(id) };
const issue = async (id = "app") =>
	String(
		(await post("/oauth/token", { grant_type: "client_credentials", ...as(id) })).body.access_token,
	);
const introspect = (token: string, by = "resource") =>
	post("/oauth/introspect", { token, ...as(by) });
const revoke = (token: string, by = "app") => post("/oauth/revoke", { token, ...as(by) });
const listOf = (aud: unknown) => (Array.isArray(aud) ? aud : [aud]);

describe("introspection", () => {
	it("describes an active token to a client allowed its audience, without caching", async () => {
		const token = await issue();
		const answer = await introspect(token);
		expect(answer.status).toBe(200);
		expect(answer.headers.get("cache-control")).toBe("no-store");
		expect(answer.body).toMatchObject({
			active: true,
			iss: "https://issuer.example",
			sub: "app",
			client_id: "app",
			scope: "read",
			token_type: "Bearer",
		});
		expect(listOf(answer.body.aud)).toContain("https://api.example");
		expect(typeof answer.body.exp).toBe("number");
	});

	it("answers inactive to a client not allowed the token's audience, and for a token it cannot verify", async () => {
		expect((await introspect(await issue(), "stranger")).body).toEqual({ active: false });
		expect((await introspect("not-a-token")).body).toEqual({ active: false });
	});

	it("refuses a public client and a wrong secret", async () => {
		const token = await issue();
		expect((await introspect(token, "pub")).status).toBe(401);
		const wrong = await post("/oauth/introspect", {
			token,
			client_id: "resource",
			client_secret: "wrong",
		});
		expect([wrong.status, wrong.body.error]).toEqual([401, "invalid_client"]);
	});

	it.skipIf(areaTarget().differs("introspection-without-token"))(
		"refuses a request without a token",
		async () => {
			const missing = await post("/oauth/introspect", as("resource"));
			expect([missing.status, missing.body.error]).toEqual([400, "invalid_request"]);
		},
	);
});

describe("revocation", () => {
	it("lets the issuing client revoke its access token", async () => {
		const token = await issue();
		const answer = await revoke(token);
		expect(answer.status).toBe(200);
		expect((await introspect(token)).body).toEqual({ active: false });
		expect((await revoke(token)).status).toBe(200);
	});

	it("answers another client 200 and leaves the token active", async () => {
		const token = await issue();
		expect((await revoke(token, "other")).status).toBe(200);
		expect((await introspect(token)).body.active).toBe(true);
	});

	it("answers 200 for a token it cannot verify", async () => {
		expect((await revoke("not-a-token")).status).toBe(200);
	});

	it("refuses a missing token and a wrong secret", async () => {
		const missing = await post("/oauth/revoke", as("app"));
		expect([missing.status, missing.body.error]).toEqual([400, "invalid_request"]);
		const wrong = await post("/oauth/revoke", {
			token: await issue(),
			client_id: "app",
			client_secret: "wrong",
		});
		expect([wrong.status, wrong.body.error]).toEqual([401, "invalid_client"]);
	});
});

describe.runIf(areaTarget().can(auditEvents.need))("revocation: audit events", () => {
	it("records a revocation by the issuing client, and nothing for another client's attempt", async () => {
		const token = await issue();
		const trail = auditEvents.of(running);
		const other = await trail.during(() => revoke(token, "other"));
		const own = await trail.during(() => revoke(token));
		expect([other.result.status, own.result.status]).toEqual([200, 200]);
		expect(other.events).toEqual([]);
		expect(own.events).toEqual([
			{
				kind: "token.revoked",
				at: expect.any(Number),
				attributes: { client: "app", source: expect.any(String), token_type: "access_token" },
			},
		]);
		expect(JSON.stringify(own.events)).not.toContain(token);
	});
});

describe.runIf(areaTarget().can("store-fault:revocations"))(
	"introspection and revocation: the store failing",
	() => {
		const faulty = faultyTarget(scene);
		let at = "";
		beforeAll(() => {
			at = base;
			base = faulty.base();
		});
		afterAll(() => {
			base = at;
		});

		it("answers 503 while the store is unreachable, never inactive or a revocation it could not write", async () => {
			const token = await issue();
			const introspected = await faulty.whileDown(() => introspect(token));
			expect([introspected.status, introspected.body.error]).toEqual([
				503,
				"temporarily_unavailable",
			]);
			const revoked = await faulty.whileDown(() => revoke(token));
			expect([revoked.status, revoked.body.error]).toEqual([503, "temporarily_unavailable"]);
			// A revocation sent while the store hung may still land, so only an answer is expected after.
			expect((await introspect(token)).status).toBe(200);
		});
	},
);
