import { generateKeyPairSync, randomBytes, sign as signWith } from "node:crypto";
import { mkdtempSync, readdirSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { createServer as createPlainServer, type Server as PlainServer } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSigned } from "@mod/conformance-front";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { converse } from "../src/dialog/dialog.ts";
import { type Flow, flows } from "../src/libraries/libraries.ts";
import { excusable, library, runs, unmetOf } from "./library.ts";
import { startWorld, type World, type WorldClient } from "./world/world.ts";

/** The flows of this file: every one but those the services' app runs. */
const here = flows.filter((f) => f !== "jwt-bearer");

let world: World;
beforeAll(async () => {
	world = await startWorld();
});
afterAll(async () => {
	await world?.stop();
});

/** Runs one flow with the library, answering its browser steps; a flow that gives no result fails. */
async function run(flow: Flow, client: WorldClient, extra: Record<string, unknown> = {}) {
	const browser = world.browser();
	const dialog = await converse(
		library.adapter(),
		{ flow, issuer: world.issuer, ca: world.ca, client, redirectUri: world.redirectUri, ...extra },
		async (ask) => {
			if (ask.ask === "browse") return { location: await browser.authorize(String(ask.url)) };
			if (ask.ask === "device") {
				expect(ask.verificationUri).toBe(`${world.issuer}/device`);
				await browser.approve(String(ask.userCode));
				return {};
			}
			if (ask.ask === "logout") return { location: await browser.endSession(String(ask.url)) };
			throw new Error(`the driver has no answer to ${ask.ask}`);
		},
		90_000,
	);
	if (dialog.outcome.kind !== "result")
		throw new Error(
			`${library.name} ${flow}: ${dialog.outcome.type}: ${dialog.outcome.message}\n${dialog.stderr.slice(-2000)}`,
		);
	return dialog.outcome.result as Record<string, unknown>;
}

const claims = (value: unknown) => value as Record<string, unknown>;

describe(`${library.name}: signing in`, () => {
	it.runIf(runs("login"))(
		"signs in by the code flow with PKCE and client_secret_basic, the ID token checked and userinfo read",
		(context) =>
			excusable(context, "login", async () => {
				const result = await run("login", world.clients.basic, { scope: "openid profile email" });
				const id = claims(result.idToken);
				expect(id.iss).toBe(world.issuer);
				expect([id.aud].flat()).toContain(world.clients.basic.id);
				expect(claims(result.userinfo).sub).toBe(id.sub);
				expect(String(result.tokenType).toLowerCase()).toBe("bearer");
			}),
	);

	it.runIf(runs("login"))("signs in with client_secret_post", (context) =>
		excusable(context, "login", async () => {
			const result = await run("login", world.clients.post);
			expect(claims(result.idToken).iss).toBe(world.issuer);
		}),
	);

	it.runIf(runs("public-login"))("signs in a public client, by PKCE alone", (context) =>
		excusable(context, "public-login", async () => {
			const result = await run("public-login", world.clients.public);
			const id = claims(result.idToken);
			expect([id.aud].flat()).toContain(world.clients.public.id);
			expect(claims(result.userinfo).sub).toBe(id.sub);
		}),
	);
});

describe(`${library.name}: refreshing`, () => {
	it.runIf(runs("refresh"))(
		"refreshes the access token, the refresh token rotated and the one it replaced refused",
		(context) =>
			excusable(context, "refresh", async () => {
				const result = await run("refresh", world.clients.post);
				expect(result).toEqual({ accessToken: true, rotated: true, replayed: "invalid_grant" });
			}),
	);
});

describe(`${library.name}: the known differences`, () => {
	it("are each met by a check of this run, so a fixed one is taken out", () => {
		expect(unmetOf(here)).toEqual([]);
	});
});

describe(`${library.name}: a discovery that names plain http`, () => {
	let server: Server;
	let origin = "";
	let cert = "";
	let told: Record<string, unknown> = {};
	// Plain http on the same host, where the token endpoint sends a request on: what reaches it, in clear.
	let plain: PlainServer;
	let plainOrigin = "";
	const reachedInClear: string[] = [];
	beforeAll(async () => {
		const tls = await selfSigned("127.0.0.1", await mkdtemp(join(tmpdir(), "interop-http-")));
		cert = tls.cert;
		plain = createPlainServer((req, res) => {
			reachedInClear.push(`${req.method} ${req.url} ${req.headers.authorization ?? ""}`);
			res.writeHead(400, { "content-type": "application/json" });
			res.end(JSON.stringify({ error: "invalid_request" }));
		});
		await new Promise<void>((resolve) => plain.listen(0, "127.0.0.1", resolve));
		plainOrigin = `http://127.0.0.1:${(plain.address() as AddressInfo).port}`;
		server = createServer(tls, (req, res) => {
			if (req.url === "/token") {
				// Sent on with its method and body (307), to the same host over plain http.
				res.writeHead(307, { location: `${plainOrigin}/token` });
				res.end();
				return;
			}
			res.writeHead(req.url === "/.well-known/openid-configuration" ? 200 : 404, {
				"content-type": "application/json",
			});
			res.end(JSON.stringify(told));
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
	});
	afterAll(async () => {
		await new Promise((resolve) => server?.close(resolve));
		await new Promise((resolve) => plain?.close(resolve));
	});

	/** The flow's end against a provider whose discovery says `endpoints`; any browser step fails it. */
	async function against(
		endpoints: Record<string, string>,
		flow: Flow = "login",
		client: WorldClient = world.clients.basic,
	) {
		told = {
			issuer: origin,
			authorization_endpoint: `${origin}/authorize`,
			token_endpoint: `${origin}/token`,
			userinfo_endpoint: `${origin}/userinfo`,
			jwks_uri: `${origin}/jwks`,
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: ["RS256"],
			...endpoints,
		};
		const dialog = await converse(
			library.adapter(),
			{ flow, issuer: origin, ca: cert, client, redirectUri: world.redirectUri, scope: "read" },
			async (ask) => {
				throw new Error(`asked ${ask.ask} before refusing plain http`);
			},
			30_000,
		);
		return dialog.outcome;
	}

	it.runIf(runs("login"))(
		"refuses a provider whose discovery names an http token endpoint, before the browser",
		async () => {
			expect(await against({ token_endpoint: "http://127.0.0.1:1/token" })).toMatchObject({
				kind: "error",
				type: "insecure",
			});
		},
	);

	it.runIf(runs("client-credentials-secret"))(
		"follows no redirect from an https token endpoint to plain http, sending its secret nowhere in clear",
		async () => {
			reachedInClear.length = 0;
			expect(await against({}, "client-credentials-secret", world.clients.service)).toMatchObject({
				kind: "error",
			});
			expect(reachedInClear).toEqual([]);
		},
	);

	it.runIf(runs("login"))(
		"refuses a provider whose discovery names an http key set, before the browser",
		async () => {
			expect(await against({ jwks_uri: "http://127.0.0.1:1/jwks" })).toMatchObject({
				kind: "error",
				type: "insecure",
			});
		},
	);
});

/**
 * A provider the harness plays itself, for what the real one never does: an ID token for another
 * audience. It records each key set request's Authorization, as a key set's host would see it.
 */
describe(`${library.name}: a provider the harness plays`, () => {
	let server: Server;
	let origin = "";
	let cert = "";
	// RS256, as the provider signs, which each adapter is set to take.
	const key = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const jwk = {
		...key.publicKey.export({ format: "jwk" }),
		kid: "played",
		alg: "RS256",
		use: "sig",
	};
	/** Each key set request's Authorization header, empty where it sent none. */
	const keySetAsked: string[] = [];
	/** The audience the next ID token names, for the client it was asked for. */
	let audienceOf = (client: string): string[] => [client];
	let nonce = "";
	let client = "";
	const encoded = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
	const idToken = () => {
		const now = Math.floor(Date.now() / 1000);
		const head = encoded({ alg: "RS256", kid: jwk.kid, typ: "JWT" });
		const body = encoded({
			iss: origin,
			sub: "alice",
			aud: audienceOf(client),
			azp: client,
			nonce,
			iat: now,
			exp: now + 300,
		});
		const signature = signWith("sha256", Buffer.from(`${head}.${body}`), key.privateKey);
		return `${head}.${body}.${signature.toString("base64url")}`;
	};
	beforeAll(async () => {
		const tls = await selfSigned("127.0.0.1", await mkdtemp(join(tmpdir(), "interop-played-")));
		cert = tls.cert;
		server = createServer(tls, (req, res) => {
			const json = (status: number, value: unknown) => {
				res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
				res.end(JSON.stringify(value));
			};
			if (req.url === "/.well-known/openid-configuration")
				return json(200, {
					issuer: origin,
					authorization_endpoint: `${origin}/authorize`,
					token_endpoint: `${origin}/token`,
					userinfo_endpoint: `${origin}/userinfo`,
					jwks_uri: `${origin}/jwks`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["RS256"],
					token_endpoint_auth_methods_supported: ["client_secret_basic"],
				});
			if (req.url === "/jwks") {
				keySetAsked.push(req.headers.authorization ?? "");
				return json(200, { keys: [jwk] });
			}
			if (req.url === "/token") {
				req.resume();
				return req.on("end", () =>
					json(200, {
						access_token: randomBytes(16).toString("base64url"),
						token_type: "Bearer",
						expires_in: 300,
						scope: "openid",
						id_token: idToken(),
					}),
				);
			}
			if (req.url === "/userinfo") return json(200, { sub: "alice" });
			return json(404, {});
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
	});
	afterAll(async () => {
		await new Promise((resolve) => server?.close(resolve));
	});

	/** The login flow against the played provider, the adapter's temporary files under `tmp`. */
	async function signIn(tmp: string, issuer = origin) {
		const adapter = library.adapter();
		client = world.clients.basic.id;
		const dialog = await converse(
			{ ...adapter, env: { ...adapter.env, TMPDIR: tmp } },
			{
				flow: "login",
				issuer,
				ca: cert,
				client: world.clients.basic,
				redirectUri: world.redirectUri,
			},
			async (ask) => {
				if (ask.ask !== "browse") throw new Error(`asked ${ask.ask}`);
				const asked = new URL(String(ask.url));
				nonce = asked.searchParams.get("nonce") ?? "";
				const back = new URL(world.redirectUri);
				back.searchParams.set("code", "played-code");
				back.searchParams.set("state", asked.searchParams.get("state") ?? "");
				return { location: back.href };
			},
			30_000,
		);
		return dialog.outcome;
	}
	const freshTmp = () => mkdtempSync(join(tmpdir(), "interop-adapter-tmp-"));

	it.runIf(runs("login"))(
		"signs in, fetching the provider's keys with no access token, and leaves no file behind",
		async () => {
			audienceOf = (c) => [c];
			keySetAsked.length = 0;
			const tmp = freshTmp();
			expect(await signIn(tmp)).toMatchObject({ kind: "result" });
			expect(keySetAsked.length).toBeGreaterThan(0);
			expect(keySetAsked).toEqual(keySetAsked.map(() => ""));
			expect(readdirSync(tmp)).toEqual([]);
		},
	);

	it.runIf(runs("login"))(
		"refuses an ID token for another audience, though its azp names the client",
		async () => {
			audienceOf = () => ["someone-else"];
			expect(await signIn(freshTmp())).toMatchObject({ kind: "error" });
		},
	);

	it.runIf(runs("login"))("leaves no file behind where its discovery fails", async () => {
		const tmp = freshTmp();
		expect(await signIn(tmp, `${origin}/nowhere`)).toMatchObject({ kind: "error" });
		expect(readdirSync(tmp)).toEqual([]);
	});
});

describe(`${library.name}: a token for one resource server`, () => {
	it.runIf(runs("resource"))(
		"asks a token for one resource server by `resource` in both requests, and gets one meant for it",
		(context) =>
			excusable(context, "resource", async () => {
				const result = await run("resource", world.clients.post, { resource: world.resource });
				// Both requests carry the parameter: the token takes the code's audience, so its own tells neither.
				expect(world.seen.authorizations.at(-1)?.searchParams.getAll("resource")).toEqual([
					world.resource,
				]);
				expect(world.seen.tokenRequests.at(-1)?.getAll("resource")).toEqual([world.resource]);
				const told = await world.introspect(String(result.accessToken));
				expect(told.active).toBe(true);
				// The client holds another audience, which a request asking none would get.
				expect([told.aud].flat()).toEqual([world.resource]);
			}),
	);
});

describe(`${library.name}: a client's own token`, () => {
	it.runIf(runs("client-credentials"))(
		"gets a token by the client credentials grant, the client authenticated by a private key JWT naming the issuer",
		(context) =>
			excusable(context, "client-credentials", async () => {
				const result = await run("client-credentials", world.clients.assertion, {
					scope: "read",
					assertionAudience: "issuer",
				});
				expect(String(result.tokenType).toLowerCase()).toBe("bearer");
				const told = await world.introspect(String(result.accessToken));
				expect(told).toMatchObject({ active: true, client_id: world.clients.assertion.id });
			}),
	);
});

describe(`${library.name}: a client's own token, by its secret`, () => {
	it.runIf(runs("client-credentials-secret"))(
		"gets a token by the client credentials grant, the client authenticated by client_secret_basic",
		(context) =>
			excusable(context, "client-credentials-secret", async () => {
				const result = await run("client-credentials-secret", world.clients.service, {
					scope: "read",
				});
				expect(String(result.tokenType).toLowerCase()).toBe("bearer");
				expect(await world.introspect(String(result.accessToken))).toMatchObject({
					active: true,
					client_id: world.clients.service.id,
				});
			}),
	);
});

describe(`${library.name}: revoking`, () => {
	it.runIf(runs("revocation"))(
		"introspects an access token as active, revokes it, and introspects it as inactive",
		(context) =>
			excusable(context, "revocation", async () => {
				const result = await run("revocation", world.clients.post);
				expect(result).toEqual({ before: true, after: false });
			}),
	);
});

describe(`${library.name}: a token bound to a key`, () => {
	it.runIf(runs("dpop"))(
		"gets an access token bound to a DPoP key, answering the nonce each endpoint asks, and reads userinfo with it",
		(context) =>
			excusable(context, "dpop", async () => {
				const result = await run("dpop", world.clients.post);
				expect(String(result.tokenType).toLowerCase()).toBe("dpop");
				expect(claims(result.userinfo).sub).toBe(result.sub);
				const told = await world.introspect(String(result.accessToken));
				expect(claims(told.cnf).jkt).toEqual(expect.any(String));
			}),
	);
});

describe(`${library.name}: a device`, () => {
	it.runIf(runs("device"))(
		"gets a token by the device authorization grant, once the user approves the code",
		(context) =>
			excusable(context, "device", async () => {
				const result = await run("device", world.clients.device, { scope: "openid read" });
				expect(String(result.tokenType).toLowerCase()).toBe("bearer");
				expect((await world.introspect(String(result.accessToken))).active).toBe(true);
			}),
	);
});

describe(`${library.name}: a public device`, () => {
	it.runIf(runs("public-device"))(
		"gets a token by the device authorization grant as a public client, once the user approves the code",
		(context) =>
			excusable(context, "public-device", async () => {
				const result = await run("public-device", world.clients.publicDevice, {
					scope: "openid read",
				});
				expect(String(result.tokenType).toLowerCase()).toBe("bearer");
				expect((await world.introspect(String(result.accessToken))).active).toBe(true);
			}),
	);
});

describe(`${library.name}: logging out`, () => {
	it.runIf(runs("logout"))(
		"ends the session by the end-session endpoint, and is sent back with its state",
		(context) =>
			excusable(context, "logout", async () => {
				const result = await run("logout", world.clients.post, {
					postLogoutRedirectUri: world.postLogoutRedirectUri,
				});
				const back = new URL(String(result.location));
				expect(`${back.origin}${back.pathname}`).toBe(world.postLogoutRedirectUri);
				expect(back.searchParams.get("state")).toBe(result.state);
			}),
	);
});

describe(`${library.name}: exchanging a token`, () => {
	it.runIf(runs("token-exchange"))(
		"exchanges a signed-in user's access token for another of the same subject, by token exchange",
		(context) =>
			excusable(context, "token-exchange", async () => {
				// The subject token the harness signs in for itself, as an app holding one would.
				const subject = await world.issue(world.clients.post);
				const result = await run("token-exchange", world.clients.post, {
					subjectToken: subject.accessToken,
					// The subject token's own scope, for a library that asks one.
					scope: "openid",
				});
				expect(result.issuedTokenType).toBe("urn:ietf:params:oauth:token-type:access_token");
				expect(await world.introspect(String(result.accessToken))).toMatchObject({
					active: true,
					sub: subject.sub,
				});
			}),
	);
});

describe(`${library.name}: a token bound to a certificate`, () => {
	it.runIf(runs("mtls"))(
		"gets a token by the client credentials grant over TLS presenting a certificate, bound to it",
		(context) =>
			excusable(context, "mtls", async () => {
				const result = await run("mtls", world.clients.mtls, {
					scope: "read",
					clientCertificate: {
						cert: world.clientCertificate.cert,
						key: world.clientCertificate.key,
					},
				});
				const told = await world.introspect(String(result.accessToken));
				expect(told.active).toBe(true);
				expect(claims(told.cnf)["x5t#S256"]).toBe(world.clientCertificate.thumbprint);
			}),
	);
});

describe(`${library.name}: told a session ended`, () => {
	it.runIf(runs("backchannel-logout"))(
		"is posted a logout token for the session it signed in, which it validates, once the session ends",
		(context) =>
			excusable(context, "backchannel-logout", async () => {
				const result = await run("backchannel-logout", world.clients.backchannel, {
					postLogoutRedirectUri: world.postLogoutRedirectUri,
					backchannel: world.backchannel,
				});
				expect(result.sub).toBe(result.signedInSub);
				expect(result.sid).toEqual(expect.any(String));
				expect(result.sid).toBe(result.signedInSid);
			}),
	);
});
