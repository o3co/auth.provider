import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, oauthScene, type TrustedIssuerScene } from "../../main.ts";

const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const issuer = "https://issuer.example";
const api = "https://api.example";
/** One issuer every organisation's agents share, its `sub` naming the organisation first. */
const agents = "https://agents.example/agents";
const devices = "https://devices.example";
const orgOf = (org: string) => `wimse://agents.example/org/${org}/agent/`;
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const provider = generateKeyPairSync("ed25519");
const agentsKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const devicesKey = generateKeyPairSync("ed25519");
const appSecret = "app-secret-0123456789abcdef";

const credentialless = (id: string): ClientScene => ({
	id,
	kind: "public",
	method: "none",
	grants: [grantType],
	scopes: ["orders:read", "orders:write"],
	defaultScopes: ["orders:read"],
	audiences: [api],
});
const clients: ClientScene[] = [
	credentialless("agents"),
	credentialless("devices"),
	{
		id: "app",
		kind: "confidential",
		method: "client_secret_post",
		secret: appSecret,
		grants: [grantType],
		scopes: ["orders:read"],
		defaultScopes: ["orders:read"],
	},
];
const agentsIssuer = (client?: string): TrustedIssuerScene => ({
	issuer: agents,
	alg: "ES256",
	publicPem: pem(agentsKey.publicKey, "spki"),
	conditions: { "subject-prefix": orgOf("acme") },
	...(client ? { client } : {}),
});
const devicesIssuer = (client?: string): TrustedIssuerScene => ({
	issuer: devices,
	alg: "EdDSA",
	publicPem: pem(devicesKey.publicKey, "spki"),
	conditions: { "subject-prefix": "device:" },
	...(client ? { client } : {}),
});
const scene = (issuers: TrustedIssuerScene[]) =>
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
		clients,
		resourceIndicators: true,
		jwtBearer: { issuers },
	});

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
/** An assertion as the shared issuer makes one: ES256, `aud` a list of one, ten minutes long. */
function assertion(claims: Record<string, unknown> = {}, iss = agents) {
	const now = Math.floor(Date.now() / 1000);
	const alg = iss === agents ? "ES256" : "EdDSA";
	const body = {
		iss,
		sub: iss === agents ? `${orgOf("acme")}a-1` : "device:d-1",
		aud: [issuer],
		iat: now,
		nbf: now - 15,
		exp: now + 600,
		jti: `j-${Math.random()}`,
		...claims,
	};
	const input = `${b64({ alg, typ: "JWT" })}.${b64(body)}`;
	const signature =
		iss === agents
			? sign("sha256", Buffer.from(input), { key: agentsKey.privateKey, dsaEncoding: "ieee-p1363" })
			: sign(null, Buffer.from(input), devicesKey.privateKey);
	return `${input}.${signature.toString("base64url")}`;
}

/** A token request; `as` names the client by its own way, none for a request naming no client. */
async function post(base: string, form: Record<string, string>, as?: "agents" | "app") {
	const naming =
		as === "app"
			? { client_id: "app", client_secret: appSecret }
			: as === "agents"
				? { client_id: "agents" }
				: {};
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ grant_type: grantType, ...naming, ...form }),
	});
	return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}
const claimsOf = (token: unknown) =>
	JSON.parse(Buffer.from(String(token).split(".")[1] ?? "", "base64url").toString());
const refusal = (res: Awaited<ReturnType<typeof post>>) => [res.status, res.body.error];

/** Starts the scene before the block's tests and stops it after them, handing back its base URL. */
function running(issuers: TrustedIssuerScene[]) {
	let started: Started;
	const at = { base: "" };
	beforeAll(async () => {
		started = await areaTarget().start(scene(issuers));
		if (started.kind !== "running") throw new Error(started.output);
		at.base = started.baseUrl;
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	return at;
}

describe.runIf(areaTarget().can("trusted-issuers"))(
	"C. jwt-bearer naming no client, by its issuer's client",
	() => {
		const at = running([agentsIssuer("agents"), devicesIssuer("devices")]);

		it("issues for a request naming no client a token for the issuer's client", async () => {
			const res = await post(at.base, { assertion: assertion() });
			expect(res.status).toBe(200);
			expect(res.body.token_type).toBe("Bearer");
			expect(claimsOf(res.body.access_token)).toMatchObject({
				client_id: "agents",
				sub: `${orgOf("acme")}a-1`,
			});
		});

		it("refuses another organisation's agent as an untrusted signer", async () => {
			const res = await post(at.base, { assertion: assertion({ sub: `${orgOf("other")}a-1` }) });
			expect([...refusal(res), res.body.error_description]).toEqual([
				400,
				"invalid_grant",
				"untrusted signer",
			]);
		});

		it("refuses the issuer's assertion to another client", async () => {
			expect(refusal(await post(at.base, { assertion: assertion() }, "app"))).toEqual([
				400,
				"invalid_grant",
			]);
		});

		it("uses an assertion up once, whether a request names the client or none", async () => {
			const first = assertion();
			expect((await post(at.base, { assertion: first })).status).toBe(200);
			expect(refusal(await post(at.base, { assertion: first }, "agents"))).toEqual([
				400,
				"invalid_grant",
			]);
			const second = assertion();
			expect((await post(at.base, { assertion: second }, "agents")).status).toBe(200);
			expect(refusal(await post(at.base, { assertion: second }))).toEqual([400, "invalid_grant"]);
		});

		it("narrows the token's scope and resource within the issuer's client's", async () => {
			const asked = await post(at.base, {
				assertion: assertion(),
				scope: "orders:write",
				resource: api,
			});
			expect(asked.status).toBe(200);
			expect(claimsOf(asked.body.access_token)).toMatchObject({ scope: "orders:write", aud: api });
			const elsewhere = await post(at.base, {
				assertion: assertion(),
				resource: "https://elsewhere.example",
			});
			expect(refusal(elsewhere)).toEqual([400, "invalid_target"]);
			expect(refusal(await post(at.base, { assertion: assertion(), scope: "admin" }))).toEqual([
				400,
				"invalid_scope",
			]);
		});
	},
);

describe.runIf(areaTarget().can("trusted-issuers"))(
	"C. jwt-bearer naming no client, its client taken off one issuer",
	() => {
		const at = running([agentsIssuer("agents"), devicesIssuer()]);

		it("refuses as an untrusted signer the issuer without a client, while another keeps one", async () => {
			const res = await post(at.base, { assertion: assertion({}, devices) });
			expect([...refusal(res), res.body.error_description]).toEqual([
				400,
				"invalid_grant",
				"untrusted signer",
			]);
			expect((await post(at.base, { assertion: assertion() })).status).toBe(200);
		});
	},
);

describe.runIf(areaTarget().can("trusted-issuers"))(
	"C. jwt-bearer naming no client, every issuer's client taken off",
	() => {
		const at = running([agentsIssuer(), devicesIssuer()]);

		it("answers a request naming no client invalid_client, as before", async () => {
			expect(refusal(await post(at.base, { assertion: assertion() }))).toEqual([
				401,
				"invalid_client",
			]);
		});
	},
);
