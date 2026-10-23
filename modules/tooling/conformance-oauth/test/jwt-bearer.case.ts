import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { areaTarget, faultyTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, oauthScene } from "../src/main.ts";

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const issuer = "https://issuer.example";
const upstream = "https://idp.example";
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const provider = generateKeyPairSync("ed25519");
const trusted = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519");
const client = (id: string, grants: string[]): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: `${id}-secret-0123456789abcdef`,
	grants,
	scopes: ["read"],
	defaultScopes: ["read"],
});
const scene = (withGrant: boolean) =>
	oauthScene({
		issuer,
		keys: {
			signing: {
				kid: "jb",
				alg: "EdDSA",
				privatePem: pem(provider.privateKey, "pkcs8"),
				publicPem: pem(provider.publicKey, "spki"),
			},
		},
		// Without the grant composed, no client may be allowed it: boot refuses a grant nothing serves.
		// Other is allowed no grant, so not this one, and the scene needs no other grant composed.
		clients: [client("app", withGrant ? [grantType] : []), client("other", [])],
		...(withGrant
			? {
					jwtBearer: {
						issuers: [
							{
								issuer: upstream,
								alg: "EdDSA" as const,
								publicPem: pem(trusted.publicKey, "spki"),
							},
						],
					},
				}
			: { jwtBearer: false as const }),
	});

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
function assertion(
	claims: Record<string, unknown>,
	key: KeyObject | undefined = trusted.privateKey,
	alg = "EdDSA",
): string {
	const now = Math.floor(Date.now() / 1000);
	const body = {
		iss: upstream,
		sub: "alice",
		aud: issuer,
		iat: now,
		exp: now + 120,
		jti: `j-${Math.random()}`,
		...claims,
	};
	const input = `${b64({ alg, typ: "JWT" })}.${b64(body)}`;
	if (!key) return `${input}.`;
	return `${input}.${sign(null, Buffer.from(input), key).toString("base64url")}`;
}

async function post(base: string, form: Record<string, string>, id = "app") {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			client_id: id,
			client_secret: `${id}-secret-0123456789abcdef`,
			...form,
		}),
	});
	return {
		status: res.status,
		headers: res.headers,
		body: (await res.json()) as Record<string, unknown>,
	};
}

describe("C. jwt-bearer when the grant is not offered", () => {
	let running: Started;
	beforeAll(async () => {
		running = await areaTarget().start(scene(false));
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
	});

	it("answers unsupported_grant_type", async () => {
		if (running.kind !== "running") throw new Error(running.output);
		const res = await post(running.baseUrl, { grant_type: grantType, assertion: assertion({}) });
		expect([res.status, res.body.error]).toEqual([400, "unsupported_grant_type"]);
	});
});

describe.runIf(areaTarget().can("trusted-issuers"))("C. jwt-bearer with a trusted issuer", () => {
	let base = "";
	let running: Started;
	beforeAll(async () => {
		running = await areaTarget().start(scene(true));
		if (running.kind !== "running") throw new Error(running.output);
		base = running.baseUrl;
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
	});

	it("issues a token that does not outlive the assertion", async () => {
		const exp = Math.floor(Date.now() / 1000) + 120;
		const res = await post(base, { grant_type: grantType, assertion: assertion({ exp }) });
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control")).toContain("no-store");
		expect(res.body.token_type).toBe("Bearer");
		expect(res.body.refresh_token).toBeUndefined();
		expect(Number(res.body.expires_in)).toBeLessThanOrEqual(120);
		const claims = JSON.parse(
			Buffer.from(String(res.body.access_token).split(".")[1] ?? "", "base64url").toString(),
		);
		expect(claims.exp).toBeLessThanOrEqual(exp);
		expect(claims.client_id).toBe("app");
	});

	it("refuses assertions that do not verify", async () => {
		const now = Math.floor(Date.now() / 1000);
		const cases = [
			assertion({}, stranger.privateKey),
			assertion({ iss: "https://unknown.example" }),
			assertion({ aud: "https://elsewhere.example" }),
			assertion({ exp: now - 600 }),
			assertion({ exp: now + 86_400 * 2 }),
			assertion({ exp: undefined }),
			assertion({ sub: undefined }),
			assertion({ iat: now + 600 }),
			assertion({ nbf: now + 600 }),
			assertion({}, undefined, "none"),
			"not-a-jwt",
		];
		for (const a of cases) {
			const res = await post(base, { grant_type: grantType, assertion: a });
			expect([res.status, res.body.error]).toEqual([400, "invalid_grant"]);
		}
	});

	it("refuses a replayed assertion", async () => {
		const a = assertion({});
		expect((await post(base, { grant_type: grantType, assertion: a })).status).toBe(200);
		expect((await post(base, { grant_type: grantType, assertion: a })).body.error).toBe(
			"invalid_grant",
		);
	});

	it("refuses a missing assertion and a client not allowed the grant", async () => {
		expect((await post(base, { grant_type: grantType })).body.error).toBe("invalid_request");
		const other = await post(base, { grant_type: grantType, assertion: assertion({}) }, "other");
		expect([other.status, other.body.error]).toEqual([400, "unauthorized_client"]);
	});
});

describe.runIf(areaTarget().can("trusted-issuers"))("O. refusals about the store", () => {
	it("refuses to start when data that must survive would sit in a store that loses it, unless accepted", async () => {
		const started = await areaTarget().start({ ...scene(true), acceptVolatileStore: false });
		if (started.kind === "running") await started.stop();
		expect(started.kind).toBe("refused");
	});
});

describe.runIf(
	areaTarget().can("trusted-issuers") && areaTarget().can("store-fault:assertion-replay"),
)("C. jwt-bearer: the store failing", () => {
	const faulty = faultyTarget(scene(true));

	it("answers 503 to an assertion while the store is unreachable, never invalid_grant", async () => {
		const res = await faulty.whileDown(() =>
			post(faulty.base(), { grant_type: grantType, assertion: assertion({}) }),
		);
		expect([res.status, res.body.error]).toEqual([503, "temporarily_unavailable"]);
	});
});
