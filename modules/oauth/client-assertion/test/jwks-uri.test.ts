import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig } from "@mod/clients/testing";
import externalJwtModule from "@mod/external-jwt/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, BootRefused, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import outboundModule from "@mod/outbound/module";
import { memoryRecords } from "@mod/records/testing";
import secretHashModule from "@mod/secret-hash/module";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { SignJWT } from "jose";
import { afterAll, beforeAll, expect, it } from "vitest";
import { spentAssertions } from "../src/contract.ts";
import { assertionType } from "../src/method.ts";
import assertionModule from "../src/module.ts";
import { type ClientAssertionSettings, clientAssertionConfig } from "../src/testing.ts";

const issuer = "https://issuer.example";
const tokenUrl = `${issuer}/oauth/token`;
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const publicJwk = (key: KeyObject, kid: string) => ({ ...key.export({ format: "jwk" }), kid });

/** A key set server on loopback, counting what it is asked; `/down` answers 503. */
let fetched = 0;
let served: unknown = { keys: [publicJwk(ec.publicKey, "ec")] };
const server = createServer((request, response) => {
	fetched++;
	if (request.url === "/down") {
		response.writeHead(503).end();
		return;
	}
	response.writeHead(200, { "content-type": "application/json" });
	response.end(JSON.stringify(served));
});
let port = 0;
beforeAll(async () => {
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	port = (server.address() as AddressInfo).port;
});
afterAll(() => new Promise<void>((done) => server.close(() => done())));
const jwksUri = () => `http://127.0.0.1:${port}/jwks`;

/** Clients over outbound reaching the key set server alone; `section` is the client's own, `algorithms` the operator's. */
async function boot(
	section: Record<string, unknown>,
	reach = true,
	algorithms?: ClientAssertionSettings["algorithms"],
) {
	const stand = memoryRecords<true>(() => Date.now(), { shards: 1, perShard: 1 });
	const location = defineModule({ name: "token-endpoint", replicaSafe: true, takes: [] }, (m) => [
		m.provide(tokenEndpointLocation).by(() => ({ url: tokenUrl })),
	]);
	const spent = defineModule({ name: "spent", replicaSafe: false, takes: [] }, (m) => [
		m
			.provide(spentAssertions)
			.by(() => ({ save: (name, lifetimeMs) => stand.records.create(name, true, lifetimeMs) })),
	]);
	const app = await assemble({
		modules: [
			http,
			outboundModule,
			tlsOptionsForTests,
			externalJwtModule,
			clientsModule,
			secretHashModule,
			issuerModule,
			assertionModule,
			spent,
			location,
		],
		config: {
			...kernelConfig(),
			outbound: reach ? { allow: ["127.0.0.1"], "plain-loopback": [`127.0.0.1:${port}`] } : {},
			...httpConfig({ "public-origin": issuer }),
			...issuerConfig({ url: issuer }),
			...clientAssertionConfig(algorithms === undefined ? {} : { algorithms }),
			...clientsConfig([
				{
					id: "app",
					kind: "confidential",
					method: "private_key_jwt",
					sections: { "client-assertion": section },
				},
			]),
		},
		runtime: quietRuntime(),
	});
	return app.get(clients);
}

const assertion = () =>
	new SignJWT({
		iss: "app",
		sub: "app",
		aud: issuer,
		exp: Math.floor(Date.now() / 1000) + 60,
		jti: `j-${Math.random()}`,
	})
		.setProtectedHeader({ alg: "ES256", kid: "ec" })
		.sign(ec.privateKey);
const authenticate = async (c: Awaited<ReturnType<typeof boot>>) =>
	c.authenticate(
		testRequest({
			method: "POST",
			form: new Map([
				["client_assertion_type", [assertionType]],
				["client_assertion", [await assertion()]],
			]),
		}),
	);

it("authenticates a client by keys it publishes at its jwks-uri, fetching the set once", async () => {
	const c = await boot({ "jwks-uri": jwksUri() });
	const before = fetched;
	for (let i = 0; i < 2; i++) {
		expect(await authenticate(c)).toMatchObject({ kind: "authenticated", client: { id: "app" } });
	}
	expect(fetched - before).toBe(1);
});

it("refuses a key its jwks-uri does not publish [rfc7523-3-u] [rfc7521-5.2-n]", async () => {
	served = {
		keys: [publicJwk(generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey, "ec")],
	};
	try {
		const c = await boot({ "jwks-uri": jwksUri() });
		expect(await authenticate(c)).toMatchObject({ kind: "refused", reason: "bad_credentials" });
	} finally {
		served = { keys: [publicJwk(ec.publicKey, "ec")] };
	}
});

it("is unavailable while the jwks-uri gives no key set", async () => {
	const c = await boot({ "jwks-uri": `http://127.0.0.1:${port}/down` });
	await expect(authenticate(c)).rejects.toSatisfy(isUnavailable);
});

it("refuses boot for a client whose jwks-uri outbound's policy refuses", async () => {
	await expect(boot({ "jwks-uri": jwksUri() }, false)).rejects.toMatchObject({
		refusals: [
			{
				where: "clients.registered.0.sections.client-assertion",
				reason: expect.stringMatching(
					/refuses the jwks-uri: not-allowed: name the host in outbound\.allow, or set outbound\.allow-any-public; plain http also needs its host:port in outbound\.plain-loopback, or, for a URL of your own configuration on a private network, in outbound\.plain-internal$/,
				),
			},
		],
	});
});

it("refuses boot for a client with both written keys and a jwks-uri, or a jwks-uri that is no URL", async () => {
	const keys = [publicJwk(ec.publicKey, "ec")];
	for (const section of [
		{ keys, "jwks-uri": jwksUri() },
		{ "jwks-uri": "not a url" },
		{ "jwks-uri": "ftp://keys.example/jwks" },
	]) {
		await expect(boot(section), JSON.stringify(section)).rejects.toBeInstanceOf(BootRefused);
	}
});

it("refuses boot for a client's written key that none of the algorithms taken reads, naming its place", async () => {
	const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const unnamed = publicJwk(rsa.publicKey, "rsa");
	for (const [keys, algorithms] of [
		// Two taken for its kind, and it names neither.
		[
			[publicJwk(ec.publicKey, "ec"), unnamed],
			["ES256", "RS256", "PS256"],
		],
		// It names one not taken.
		[[{ ...unnamed, alg: "RS512" }], ["RS256", "ES256"]],
	] as const) {
		await expect(boot({ keys }, true, [...algorithms])).rejects.toMatchObject({
			refusals: [
				{
					where: "clients.registered.0.sections.client-assertion",
					reason: `keys.${keys.length - 1} is read under none of client-assertion.algorithms: give it an alg among them, or take only one for its kind`,
				},
			],
		});
	}
	// Each such key is named, in one refusal.
	await expect(
		boot({ keys: [unnamed, publicJwk(ec.publicKey, "ec"), { ...unnamed, alg: "RS512" }] }, true, [
			"RS256",
			"PS256",
			"ES256",
		]),
	).rejects.toMatchObject({
		refusals: [
			{
				reason:
					"keys.0, keys.2 are read under none of client-assertion.algorithms: give each an alg among them, or take only one for its kind",
			},
		],
	});
	// Named, or one taken for its kind, it is read under that one.
	await boot({ keys: [{ ...unnamed, alg: "PS256" }] }, true, ["RS256", "PS256"]);
	await boot({ keys: [unnamed] }, true, ["RS256", "ES256"]);
	await boot({ keys: [unnamed, publicJwk(ec.publicKey, "ec")] });
});
