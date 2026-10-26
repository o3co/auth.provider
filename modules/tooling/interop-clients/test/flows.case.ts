import { mkdtemp } from "node:fs/promises";
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
				const result = await run("refresh", world.clients.basic);
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
	beforeAll(async () => {
		const tls = await selfSigned("127.0.0.1", await mkdtemp(join(tmpdir(), "interop-http-")));
		cert = tls.cert;
		server = createServer(tls, (req, res) => {
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
	});

	/** The flow's end against a provider whose discovery says `endpoints`; any browser step fails it. */
	async function against(endpoints: Record<string, string>) {
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
			{
				flow: "login",
				issuer: origin,
				ca: cert,
				client: world.clients.basic,
				redirectUri: world.redirectUri,
			},
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

describe(`${library.name}: a token for one resource server`, () => {
	it.runIf(runs("resource"))(
		"asks a token for one resource server by `resource` in both requests, and gets one meant for it",
		(context) =>
			excusable(context, "resource", async () => {
				const result = await run("resource", world.clients.basic, { resource: world.resource });
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

describe(`${library.name}: revoking`, () => {
	it.runIf(runs("revocation"))(
		"introspects an access token as active, revokes it, and introspects it as inactive",
		(context) =>
			excusable(context, "revocation", async () => {
				const result = await run("revocation", world.clients.basic);
				expect(result).toEqual({ before: true, after: false });
			}),
	);
});

describe(`${library.name}: a token bound to a key`, () => {
	it.runIf(runs("dpop"))(
		"gets an access token bound to a DPoP key, answering the nonce each endpoint asks, and reads userinfo with it",
		(context) =>
			excusable(context, "dpop", async () => {
				const result = await run("dpop", world.clients.basic);
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

describe(`${library.name}: logging out`, () => {
	it.runIf(runs("logout"))(
		"ends the session by the end-session endpoint, and is sent back with its state",
		(context) =>
			excusable(context, "logout", async () => {
				const result = await run("logout", world.clients.basic, {
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
				const result = await run("token-exchange", world.clients.basic);
				expect(result.issuedTokenType).toBe("urn:ietf:params:oauth:token-type:access_token");
				expect(await world.introspect(String(result.accessToken))).toMatchObject({
					active: true,
					sub: result.sub,
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
