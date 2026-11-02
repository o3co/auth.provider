import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ClientScene, oauthScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const upstream = "https://idp.example";
const jwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const [first, second, unlisted] = ["https://a.example", "https://b.example", "https://c.example"];
const pem = (k: KeyObject, type: "pkcs8" | "spki") => k.export({ format: "pem", type }).toString();
const provider = generateKeyPairSync("ed25519");
const trusted = generateKeyPairSync("ed25519");
const client = (id: string, grants: string[]): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_post",
	secret: `${id}-secret-0123456789abcdef`,
	grants,
	scopes: ["read"],
	defaultScopes: ["read"],
	audiences: [first, second],
});
const scene = (resourceIndicators: boolean, withJwtBearer = false) =>
	oauthScene({
		issuer,
		keys: {
			signing: {
				kid: "ri",
				alg: "EdDSA",
				privatePem: pem(provider.privateKey, "pkcs8"),
				publicPem: pem(provider.publicKey, "spki"),
			},
		},
		// Each scene only the client of its grant, so it needs no other grant composed.
		clients: withJwtBearer
			? [client("bearer", [jwtBearer])]
			: [client("app", ["client_credentials"])],
		resourceIndicators,
		...(withJwtBearer
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
			: {}),
	});

/** A target started with the scene for the tests of the describe it is called in. */
function running(build: () => ReturnType<typeof scene>) {
	let started: Started;
	const at = { base: "" };
	beforeAll(async () => {
		started = await areaTarget().start(build());
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
		at.base = started.baseUrl;
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	/** A token request by the client, its fields given in order, a field repeated where given twice. */
	const token = async (id: string, fields: [string, string][]) => {
		const res = await fetch(`${at.base}/oauth/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams([
				["client_id", id],
				["client_secret", `${id}-secret-0123456789abcdef`],
				...fields,
			]),
		});
		const body = (await res.json()) as Record<string, unknown>;
		const claims =
			typeof body.access_token === "string"
				? JSON.parse(Buffer.from(body.access_token.split(".")[1] ?? "", "base64url").toString())
				: {};
		const aud = claims.aud === undefined ? undefined : [claims.aud].flat();
		return { status: res.status, error: body.error, aud };
	};
	return { token };
}
const credentials = (resources: string[]): [string, string][] => [
	["grant_type", "client_credentials"],
	...resources.map((r): [string, string] => ["resource", r]),
];

describe("RFC 8707: client credentials narrowed to a resource", () => {
	const s = running(() => scene(true));

	it("issues for the one resource asked among the client's audiences, and its first audience when none is asked [rfc8707-2-c]", async () => {
		expect(await s.token("app", credentials([second]))).toMatchObject({
			status: 200,
			aud: [second],
		});
		expect(await s.token("app", credentials([]))).toMatchObject({ status: 200, aud: [first] });
	});

	it("refuses a resource outside the client's audiences with invalid_target", async () => {
		expect(await s.token("app", credentials([unlisted]))).toMatchObject({
			status: 400,
			error: "invalid_target",
		});
	});

	it.skipIf(areaTarget().differs("resource-repeated"))(
		"refuses a repeated resource, the same or another, as a target it cannot meet: one audience is issued",
		async () => {
			for (const twice of [
				[first, first],
				[first, second],
			]) {
				expect(await s.token("app", credentials(twice)), twice.join(" ")).toMatchObject({
					status: 400,
					error: "invalid_target",
				});
			}
		},
	);

	it.skipIf(areaTarget().differs("resource-client-id"))(
		"refuses the client's own id as a resource it was not given as an audience",
		async () => {
			expect(await s.token("app", credentials(["app"]))).toMatchObject({
				status: 400,
				error: "invalid_target",
			});
		},
	);
});

describe("RFC 8707: off unless composed", () => {
	const s = running(() => scene(false));

	it("reads no resource, issuing for the client's first audience", async () => {
		expect(await s.token("app", credentials([unlisted]))).toMatchObject({
			status: 200,
			aud: [first],
		});
	});
});

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
function assertion(): string {
	const now = Math.floor(Date.now() / 1000);
	const body = {
		iss: upstream,
		sub: "alice",
		aud: issuer,
		iat: now,
		exp: now + 120,
		jti: `j-${Math.random()}`,
	};
	const input = `${b64({ alg: "EdDSA", typ: "JWT" })}.${b64(body)}`;
	return `${input}.${sign(null, Buffer.from(input), trusted.privateKey).toString("base64url")}`;
}
const bearer = (resources: string[]): [string, string][] => [
	["grant_type", jwtBearer],
	["assertion", assertion()],
	...resources.map((r): [string, string] => ["resource", r]),
];

describe.runIf(areaTarget().can("trusted-issuers"))(
	"RFC 8707: jwt-bearer narrowed to a resource",
	() => {
		const s = running(() => scene(true, true));

		it("issues for the resource asked among the client's audiences, and refuses one outside them [rfc8707-2-c]", async () => {
			expect(await s.token("bearer", bearer([second]))).toMatchObject({
				status: 200,
				aud: [second],
			});
			expect(await s.token("bearer", bearer([unlisted]))).toMatchObject({
				status: 400,
				error: "invalid_target",
			});
		});
	},
);
