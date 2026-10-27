import { type AuditEvent, audit } from "@mod/audit";
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { authMethods } from "@mod/clients";
import clientEvents from "@mod/clients/audit-events";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import { type Grant, grants, sessionIssuances, targetRules } from "@mod/grants";
import { listening } from "@mod/http";
import { assemble, BootRefused, defineModule, type Module, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { senderBindings } from "@mod/sender-binding";
import { simulatedStore } from "@mod/store/testing";
import { type AddedClaims, type IssuanceRequest, issuancePolicies } from "@mod/tokens";
import { afterEach, describe, expect, it } from "vitest";
import declared from "../src/audit-events.ts";
import { tokenEndpointLocation } from "../src/contract.ts";
import { basicOf, endpointConfig, endpointModules } from "./deployment.ts";

const logged = recordingLog();
const quiet = quietRuntime({
	log: logged.log,
	clock: { now: () => 1_800_000_000_000 },
	random: { bytes: (n) => new Uint8Array(n).fill(1) },
});
const client = (
	id: string,
	method: string,
	extra: Record<string, unknown> = {},
	more: Record<string, unknown> = {},
) => {
	const sections = {
		...allowancesFor({
			grants: ["client_credentials"],
			scopes: ["read", "write"],
			"default-scopes": ["read"],
			...extra,
		}),
		...more,
	};
	return method === "none"
		? publicClient({ id, sections })
		: confidentialClient({ id, method, sections });
};

let stop = async () => {};
afterEach(() => stop());
/** The audit events of the latest `serve`. */
let events: readonly AuditEvent[] = [];
// Every event a test records is one the module declares, with attributes it declares.
afterEach(() => {
	for (const { kind, attributes } of events) {
		const all: Readonly<Record<string, { readonly attributes: readonly string[] }>> = {
			...clientEvents,
			...declared,
		};
		const known: readonly string[] = all[kind]?.attributes ?? [];
		expect(known, `${kind} is declared`).not.toEqual([]);
		expect(
			Object.keys(attributes ?? {}).filter((name) => !known.includes(name)),
			kind,
		).toEqual([]);
	}
	events = [];
});

/** The endpoint with `extra` modules and `clients` besides the usual, its `settings`, and http's `peer` settings. */
/** Clients allowed the test grants, registered only where a test composes those grants. */
const echoClients = {
	echo: () => client("echo", "client_secret_basic", { grants: ["urn:test:echo"] }),
	pubecho: () => client("pubecho", "none", { grants: ["urn:test:echo"] }),
	echoes: () =>
		client("echoes", "client_secret_basic", { grants: ["urn:test:echo", "urn:test:other"] }),
};

async function serve(
	extra: Module[] = [],
	{
		settings = {},
		peer = {},
		clients = [],
	}: {
		settings?: object;
		peer?: Record<string, unknown>;
		clients?: ReturnType<typeof client>[];
	} = {},
) {
	const recorded = auditStandIn();
	events = recorded.events;
	const app = await assemble({
		modules: endpointModules(
			clientAllowanceModule,
			rateLimitModule,
			recorded.module,
			simulatedStore().module,
			...extra,
		),
		config: {
			...endpointConfig({ peer: peer, issuer: "https://issuer.example" }),
			...clientsConfig([
				client("basic", "client_secret_basic", { audiences: ["https://api"] }),
				client("narrow", "client_secret_basic", { audiences: ["https://api", "https://two"] }),
				client("post", "client_secret_post"),
				client("pub", "none"),
				client("nogrant", "client_secret_basic", { grants: [] }),
				client("noscope", "client_secret_basic", { scopes: [], "default-scopes": [] }),
				client("emptydefault", "client_secret_basic", { "default-scopes": [] }),
				client("nodefault", "client_secret_basic", { "default-scopes": undefined }),
				...clients,
			]),
			"token-endpoint": settings,
		},
		runtime: quiet,
	});
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}/oauth/token`;
	const types = {
		form: "application/x-www-form-urlencoded",
		json: "application/json",
		text: "text/plain",
	};
	/** Posts `form` as client `id` (Basic, with its secret unless `secret` is given), as a body of type `as`. */
	const post = async (
		form: Record<string, unknown> | URLSearchParams,
		id?: string,
		{ secret = `${id}-secret`, as = "form" }: { secret?: string; as?: keyof typeof types } = {},
	) => {
		const headers: Record<string, string> = { "content-type": types[as] };
		if (id) headers.authorization = basicOf(id, secret);
		const body =
			as === "json" ? JSON.stringify(form) : String(new URLSearchParams(form as URLSearchParams));
		const res = await fetch(base, { method: "POST", headers, body });
		return {
			status: res.status,
			headers: res.headers,
			body: JSON.parse((await res.text()) || "{}") as Record<string, unknown>,
		};
	};
	return Object.assign(post, { url: base });
}

/**
 * A rule narrowing to the `resource` asked when the issuance may have it, as resource indicators do;
 * strict, it also refuses a `resource` sent to a grant that takes no audience.
 */
const narrowing = (name = "narrowing", strict = false) =>
	defineModule({ name, takes: [] }, (m) => [
		m.contribute(targetRules).by(() => ({
			...(strict
				? {
						untargeted: ({ param }: { param: (name: string) => string | undefined }) =>
							param("resource")
								? ({
										kind: "error",
										error: "invalid_target",
										description: "no resource here",
									} as const)
								: undefined,
						repeated: (name: string) =>
							name === "resource"
								? ({ kind: "error", error: "invalid_target", description: "one resource" } as const)
								: undefined,
					}
				: {}),
			target: ({ param, audience, within }) => {
				const asked = param("resource");
				if (!asked) return { kind: "audience", audience };
				return within(asked)
					? { kind: "audience", audience: [asked] }
					: { kind: "error", error: "invalid_target", description: `not ${asked}` };
			},
		})),
	]);
/** The claims of the access token in a success's body. */
const claimsOf = (body: Record<string, unknown>) =>
	JSON.parse(Buffer.from(String(body.access_token).split(".")[1] ?? "", "base64url").toString());
const audienceOf = (body: Record<string, unknown>) => claimsOf(body).aud;

describe("the audience a request asks for", () => {
	it("narrows client credentials by the composed rule, within what the client may be issued", async () => {
		const post = await serve([narrowing("strict", true)]);
		const asked = (resource?: string) =>
			post({ grant_type: "client_credentials", ...(resource ? { resource } : {}) }, "narrow");
		expect(audienceOf((await asked("https://two")).body)).toBe("https://two");
		expect(audienceOf((await asked()).body)).toBe("https://api");
		expect((await asked("https://elsewhere")).body).toEqual({
			error: "invalid_target",
			error_description: "not https://elsewhere",
		});
	});

	it("reads no resource where no rule is composed", async () => {
		const post = await serve();
		const issued = await post(
			{ grant_type: "client_credentials", resource: "https://two" },
			"narrow",
		);
		expect(audienceOf(issued.body)).toBe("https://api");
	});

	it("refuses, before the grant runs, an audience asked of a grant that takes none, where the rule says so", async () => {
		const handled: string[] = [];
		const echoes = defineModule({ name: "echoes", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async () => {
					handled.push("echo");
					return { kind: "issued", body: { by: "echo" } };
				},
			})),
			m.contribute(grants).by(() => ({
				grantType: "urn:test:other",
				readsAmbient: "none",
				targets: true,
				handle: async () => {
					handled.push("other");
					return { kind: "issued", body: { by: "other" } };
				},
			})),
		]);
		const post = await serve([echoes, narrowing("strict", true)], {
			clients: [echoClients.echoes()],
		});
		const resource = "https://two";
		expect((await post({ grant_type: "urn:test:echo", resource }, "echoes")).body).toEqual({
			error: "invalid_target",
			error_description: "no resource here",
		});
		expect(handled).toEqual([]);
		expect(events.at(-1)).toMatchObject({
			kind: "token.issued.failure",
			attributes: { grant_type: "urn:test:echo", reason: "untargeted", error: "invalid_target" },
		});
		expect((await post({ grant_type: "urn:test:echo" }, "echoes")).body).toEqual({ by: "echo" });
		expect((await post({ grant_type: "urn:test:other", resource }, "echoes")).body).toEqual({
			by: "other",
		});
		expect(handled).toEqual(["echo", "other"]);
	});

	it("answers a parameter the rule reads sent twice as the rule says, and any other as a malformed request [rfc6749-3.2-d]", async () => {
		const twice = new URLSearchParams([
			["grant_type", "client_credentials"],
			["resource", "https://two"],
			["resource", "https://api"],
		]);
		const strict = await serve([narrowing("strict", true)]);
		expect((await strict(twice, "narrow")).body).toEqual({
			error: "invalid_target",
			error_description: "one resource",
		});
		expect(events.at(-1)).toMatchObject({
			attributes: { reason: "repeated_parameter", error: "invalid_target" },
		});
		const scopes = new URLSearchParams([
			["grant_type", "client_credentials"],
			["scope", "read"],
			["scope", "write"],
		]);
		expect((await strict(scopes, "narrow")).body).toMatchObject({ error: "invalid_request" });
		await stop();
		const plain = await serve([narrowing()]);
		expect((await plain(twice, "narrow")).body).toMatchObject({ error: "invalid_request" });
	});

	it("leaves an audience asked of a grant that takes none to the grant where the rule says nothing of it", async () => {
		const echo = defineModule({ name: "echo", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async () => ({ kind: "issued", body: { by: "echo" } }),
			})),
		]);
		const post = await serve([echo, narrowing()], { clients: [echoClients.echo()] });
		expect(
			(await post({ grant_type: "urn:test:echo", resource: "https://two" }, "echo")).body,
		).toEqual({ by: "echo" });
	});

	it("refuses to boot with a grant that does not say what it reads that a browser sends by itself", async () => {
		const silent = defineModule({ name: "silent", takes: [] }, (m) => [
			m.contribute(grants).by(
				() =>
					({
						grantType: "urn:test:silent",
						handle: async () => ({ kind: "issued", body: {} }),
					}) as unknown as Grant,
			),
		]);
		await expect(serve([silent])).rejects.toSatisfy(
			(error) =>
				error instanceof BootRefused &&
				error.refusals.some(
					(r) =>
						r.where === "grants:urn:test:silent" &&
						r.reason === "declares neither readsAmbient none nor cookie",
				),
		);
	});

	it("refuses to boot with two rules", async () => {
		await expect(serve([narrowing("one"), narrowing("two")])).rejects.toSatisfy(
			(error) =>
				error instanceof BootRefused && JSON.stringify(error.refusals).includes("target-rules"),
		);
	});
});

describe("token endpoint", () => {
	it("issues client credentials tokens with basic and post [rfc6749-2.3.1-a] [rfc6749-5.1-a] [rfc6749-5.1-b] [rfc6749-3.3-a]", async () => {
		const post = await serve();
		const basic = await post({ grant_type: "client_credentials", scope: "read write" }, "basic");
		expect(basic.status).toBe(200);
		expect(basic.headers.get("cache-control")).toBe("no-store");
		expect(basic.body).toMatchObject({
			token_type: "Bearer",
			expires_in: 3600,
			scope: "read write",
		});
		expect(claimsOf(basic.body)).toMatchObject({
			iss: "https://issuer.example",
			sub: "basic",
			client_id: "basic",
			aud: "https://api",
		});
		const viaPost = await post({
			grant_type: "client_credentials",
			client_id: "post",
			client_secret: "post-secret",
		});
		expect(viaPost.body).toMatchObject({ scope: "read" });
	});

	it("issues a client's default scopes when none is asked, none when it has none, and refuses a client with no default [rfc6749-3.3-b]", async () => {
		const post = await serve();
		const noscope = await post({ grant_type: "client_credentials" }, "noscope");
		expect(noscope.status).toBe(200);
		expect(noscope.body.scope).toBeUndefined();
		const empty = await post({ grant_type: "client_credentials" }, "emptydefault");
		expect([empty.status, empty.body.scope]).toEqual([200, undefined]);
		expect((await post({ grant_type: "client_credentials" }, "nodefault")).body.error).toBe(
			"invalid_scope",
		);
	});

	it("lets a listed origin's page send a body's type and its DPoP proof, and read the nonce, the challenge and the wait [oidc-discovery-3-aj]", async () => {
		const post = await serve([], { peer: { "cors-origins": ["https://app.example"] } });
		const origin = "https://app.example";
		const preflight = await fetch(post.url, {
			method: "OPTIONS",
			headers: {
				origin,
				"access-control-request-method": "POST",
				"access-control-request-headers": "content-type, dpop",
			},
		});
		expect(preflight.headers.get("access-control-allow-origin")).toBe(origin);
		const allowed = (preflight.headers.get("access-control-allow-headers") ?? "").toLowerCase();
		for (const name of ["content-type", "dpop"]) expect(allowed).toContain(name);
		const answered = await fetch(post.url, {
			method: "POST",
			headers: { origin, "content-type": "application/x-www-form-urlencoded" },
			body: "grant_type=client_credentials&client_id=pub",
		});
		expect(answered.headers.get("access-control-allow-origin")).toBe(origin);
		expect(
			answered.headers.get("access-control-expose-headers")?.toLowerCase().split(/,\s*/),
		).toEqual(expect.arrayContaining(["dpop-nonce", "www-authenticate", "retry-after"]));
	});

	it("limits requests per source before any client is authenticated [rfc6749-2.3.1-c] [guarantee-10-a]", async () => {
		const post = await serve([], { settings: { requests: 2, window: "2m" } });
		const wrong = () => post({ grant_type: "client_credentials" }, "basic", { secret: "wrong" });
		expect([(await wrong()).status, (await wrong()).status]).toEqual([401, 401]);
		const limited = await post({ grant_type: "client_credentials" }, "basic");
		expect([limited.status, limited.headers.get("retry-after"), limited.body]).toEqual([
			429,
			"120",
			{ error: "rate_limited" },
		]);
	});

	it("answers credentials a method finds malformed as a malformed request", async () => {
		const half = defineModule({ name: "half", takes: [] }, (m) => [
			m.contribute(authMethods).by(() => ({
				name: "half",
				claimed: (r) => r.form.get("half_id")?.[0],
				malformed: (r) => r.form.has("half_id") !== r.form.has("half_proof"),
				verify: async () => false,
			})),
		]);
		const post = await serve([half]);
		const refused = await post({ grant_type: "client_credentials", half_proof: "p" });
		expect([refused.status, refused.body.error, refused.headers.get("www-authenticate")]).toEqual([
			400,
			"invalid_request",
			null,
		]);
	});

	it("answers each refusal with its OAuth error [rfc6749-5.2-b] [rfc6749-3.2.1-a] [rfc6749-4.4-a] [rfc6749-4.4.2-a]", async () => {
		const post = await serve();
		const cc = { grant_type: "client_credentials" };
		const wrong = await post(cc, "basic", { secret: "nope" });
		expect([
			wrong.status,
			wrong.body.error,
			wrong.headers.get("www-authenticate")?.startsWith("Basic"),
		]).toEqual([401, "invalid_client", true]);
		expect((await post(cc)).status, "no client").toBe(401);
		expect((await post(cc, "nogrant")).body.error, "grant not allowed").toBe("unauthorized_client");
		expect((await post({ ...cc, scope: "admin" }, "basic")).body.error, "scope not allowed").toBe(
			"invalid_scope",
		);
		expect((await post({ grant_type: "foo" }, "basic")).body.error, "unknown grant type").toBe(
			"unsupported_grant_type",
		);
		expect((await post({}, "basic")).body.error, "no grant_type").toBe("invalid_request");
		expect((await post({ ...cc, client_id: "pub" })).body.error, "public client").toBe(
			"unauthorized_client",
		);
	});

	it("refuses a client that must bind and shows no binding, or one of a kind it does not name, before the grant runs", async () => {
		let ran = 0;
		const kinds = defineModule({ name: "kinds", takes: [] }, (m) => [
			...(
				[
					["one", "first"],
					["two", "second"],
				] as const
			).map(([name, field]) =>
				m.contribute(senderBindings).by(() => ({
					member: `m-${name}`,
					name,
					tokenType: "Test",
					read: async (request) =>
						request.form.has(field)
							? ({ kind: "bound", confirmation: "k" } as const)
							: ({ kind: "absent" } as const),
				})),
			),
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async () => {
					ran++;
					return { kind: "issued", body: {} };
				},
			})),
		]);
		const grantsEcho = { grants: ["urn:test:echo"] };
		const post = await serve([kinds], {
			clients: [
				client("must", "client_secret_basic", grantsEcho, { "sender-binding": { required: true } }),
				client("oneonly", "client_secret_basic", grantsEcho, {
					"sender-binding": { kinds: ["one"] },
				}),
			],
		});
		const echo = { grant_type: "urn:test:echo" };
		const unbound = await post(echo, "must");
		expect([unbound.status, unbound.body.error]).toEqual([400, "invalid_request"]);
		const other = await post({ ...echo, second: "1" }, "oneonly");
		expect([other.status, other.body.error]).toEqual([400, "unauthorized_client"]);
		expect(ran).toBe(0);
		expect(events.map((e) => e.attributes?.reason)).toEqual([
			"binding_required",
			"binding_kind_not_named",
		]);
		expect((await post({ ...echo, first: "1" }, "must")).status).toBe(200);
		expect((await post({ ...echo, first: "1" }, "oneonly")).status).toBe(200);
		expect((await post(echo, "oneonly")).status).toBe(200);
		expect(ran).toBe(3);
	});

	it("names the claims a grant added to the tokens it issued, never their values, in the order of their names", async () => {
		const claimed = (name: string, sets: readonly AddedClaims[]) =>
			defineModule({ name, takes: [] }, (m) => [
				m.contribute(grants).by(() => ({
					grantType: name === "twice" ? "urn:test:echo" : "urn:test:other",
					readsAmbient: "none",
					handle: async (input) => {
						for (const claims of sets) {
							const base = { subject: "sue", issuedTo: input.client.id, audience: [], scope: [] };
							const grant = Object.keys(claims).length > 0 ? { ...base, claims } : base;
							const issued = await input.issue(grant);
							if (issued.kind !== "issued") return { kind: "refused", refusal: issued.refusal };
						}
						return { kind: "issued", body: {} };
					},
				})),
			]);
		const post = await serve(
			[
				claimed("twice", [
					{ "zeta.example": "z-value", "alpha.example": 1 },
					{ "alpha.example": 2, "mid.example": true },
				]),
				claimed("none", [{}]),
			],
			{ clients: [echoClients.echoes()] },
		);
		expect((await post({ grant_type: "urn:test:echo" }, "echoes")).status).toBe(200);
		expect(events.at(-1)).toMatchObject({
			kind: "token.issued",
			attributes: { claims: "alpha.example mid.example zeta.example" },
		});
		expect(JSON.stringify(events.at(-1))).not.toContain("z-value");
		expect((await post({ grant_type: "urn:test:other" }, "echoes")).status).toBe(200);
		expect(events.at(-1)?.attributes).not.toHaveProperty("claims");
	});

	it("names every added claim while they fit in 2048 characters, else as many as fit and how many it left out", async () => {
		const named = (length: number, count: number) =>
			Object.fromEntries(
				Array.from({ length: count }, (_, i) => [
					`${String(i).padStart(2, "0")}${"n".repeat(length - 2)}`,
					0,
				]),
			);
		const issuing = (claims: Record<string, number>) =>
			defineModule({ name: "many", takes: [] }, (m) => [
				m.contribute(grants).by(() => ({
					grantType: "urn:test:echo",
					readsAmbient: "none",
					handle: async (input) => {
						const base = { subject: "sue", issuedTo: input.client.id, audience: [], scope: [] };
						const issued = await input.issue({ ...base, claims });
						return issued.kind === "issued"
							? { kind: "issued", body: {} }
							: { kind: "refused", refusal: issued.refusal };
					},
				})),
			]);
		// Eight names of 255 characters fill 2047, one space apart: all are named.
		const fits = await serve([issuing(named(255, 8))], { clients: [echoClients.echo()] });
		expect((await fits({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		const all = events.at(-1)?.attributes;
		expect([String(all?.claims).split(" ").length, all?.claims_left]).toEqual([8, undefined]);
		await stop();
		// Twelve of 200: ten fit, and two are left out.
		const over = await serve([issuing(named(200, 12))], { clients: [echoClients.echo()] });
		expect((await over({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		const cut = events.at(-1)?.attributes;
		expect([String(cut?.claims).length <= 2048, String(cut?.claims).split(" ").length]).toEqual([
			true,
			10,
		]);
		expect(cut?.claims_left).toBe("2");
	});

	it("names all at exactly 2048 characters, and leaves one out at 2049", async () => {
		/** Eight names of 227 characters and one of `last`, sorted by their first two digits. */
		const names = (last: number) =>
			Object.fromEntries(
				Array.from({ length: 9 }, (_, i) => {
					const length = i === 8 ? last : 227;
					return [`${String(i).padStart(2, "0")}${"n".repeat(length - 2)}`, 0];
				}),
			);
		const issuing = (claims: Record<string, number>) =>
			defineModule({ name: "edge", takes: [] }, (m) => [
				m.contribute(grants).by(() => ({
					grantType: "urn:test:echo",
					readsAmbient: "none",
					handle: async (input) => {
						const base = { subject: "sue", issuedTo: input.client.id, audience: [], scope: [] };
						const issued = await input.issue({ ...base, claims });
						return issued.kind === "issued"
							? { kind: "issued", body: {} }
							: { kind: "refused", refusal: issued.refusal };
					},
				})),
			]);
		// 8 × 227 + 8 spaces + 224 = 2048.
		const exact = await serve([issuing(names(224))], { clients: [echoClients.echo()] });
		expect((await exact({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		const all = events.at(-1)?.attributes;
		expect([String(all?.claims).length, all?.claims_left]).toEqual([2048, undefined]);
		await stop();
		const over = await serve([issuing(names(225))], { clients: [echoClients.echo()] });
		expect((await over({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		const cut = events.at(-1)?.attributes;
		expect([String(cut?.claims).split(" ").length, cut?.claims_left]).toEqual([8, "1"]);
	});

	it("records each issuance and each refusal it decides, with the client and the source, never a token or secret", async () => {
		const polled = defineModule({ name: "polled", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async () => ({ kind: "error", error: "authorization_pending" }),
			})),
			m.contribute(senderBindings).by(() => ({
				member: "test",
				tokenType: "Test",
				read: async (request) => {
					if (request.form.has("down")) {
						const headers = { "retry-after": "1" };
						return { kind: "refused", error: "test_down", unavailable: true, headers };
					}
					return request.form.has("bind")
						? { kind: "refused", error: "invalid_test_proof" }
						: { kind: "absent" };
				},
			})),
		]);
		const post = await serve([polled], { clients: [echoClients.echo()] });
		const cc = { grant_type: "client_credentials" };
		expect((await post(cc, "basic")).status).toBe(200);
		// Refused before the client is known: the authentication's failure, naming no client.
		await post(cc, "basic", { secret: "nope" });
		// A grant type nothing dispatches to is recorded without its name.
		await post({ grant_type: "foo" }, "basic");
		await post({}, "basic");
		await post(cc, "nogrant");
		await post({ ...cc, scope: "admin" }, "basic");
		await post({ ...cc, bind: "1" }, "basic");
		// A binding that cannot tell is 503 with its headers, and not recorded.
		const down = await post({ ...cc, down: "1" }, "basic");
		expect([down.status, down.body.error, down.headers.get("retry-after")]).toEqual([
			503,
			"test_down",
			"1",
		]);
		await post({ grant_type: "urn:test:echo" }, "echo");
		const at = quiet.clock.now();
		const source = "127.0.0.1";
		const failed = (client: string, attributes: Record<string, string>) => ({
			kind: "token.issued.failure",
			at,
			attributes: { client, source, ...attributes },
		});
		expect(events).toEqual([
			{ kind: "token.issued", at, attributes: { client: "basic", source, ...cc } },
			{
				kind: "client.authentication.failure",
				at,
				attributes: { source, reason: "bad_credentials" },
			},
			failed("basic", { reason: "unsupported_grant_type", error: "unsupported_grant_type" }),
			failed("basic", { reason: "missing_grant_type", error: "invalid_request" }),
			failed("nogrant", { ...cc, reason: "grant_type_not_allowed", error: "unauthorized_client" }),
			failed("basic", { ...cc, reason: "grant_refused", error: "invalid_scope" }),
			failed("basic", { ...cc, reason: "binding_refused", error: "invalid_test_proof" }),
			failed("echo", {
				grant_type: "urn:test:echo",
				reason: "grant_refused",
				error: "authorization_pending",
			}),
		]);
		expect(JSON.stringify(events)).not.toMatch(/secret|nope|foo/);
	});

	it("never records a proxy's address as the source: the limit answers an undetermined sender first [guarantee-10-a]", async () => {
		const post = await serve([], { peer: { "trusted-proxies": ["127.0.0.1"] } });
		const res = await post({ grant_type: "client_credentials" }, "basic");
		expect([res.status, events]).toEqual([503, []]);
	});

	it("answers a grant that cannot tell with 503 temporarily_unavailable, unaudited, logging what and the grant type", async () => {
		const down = defineModule({ name: "down", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async () => {
					throw new Unavailable("test");
				},
			})),
		]);
		const post = await serve([down], { clients: [echoClients.echo()] });
		const before = logged.lines().length;
		const res = await post({ grant_type: "urn:test:echo", scope: "kept-out" }, "echo");
		expect([res.status, res.body, events]).toEqual([503, { error: "temporarily_unavailable" }, []]);
		expect(logged.lines().slice(before)).toEqual([
			{
				level: "warn",
				event: "http.unavailable",
				fields: { what: "test", route: "/oauth/token", grant_type: "urn:test:echo" },
			},
		]);
	});

	it("keeps a grant type nothing dispatches to out of the log when it cannot tell, as the client's own input", async () => {
		const down = defineModule({ name: "audit", takes: [] }, (m) => [
			m.provide(audit).by(() => ({
				record: () => {
					throw new Unavailable("audit");
				},
				lost: () => ({}),
			})),
		]);
		const app = await assemble({
			modules: endpointModules(clientAllowanceModule, rateLimitStandIn, down),
			config: { ...endpointConfig(), ...clientsConfig([client("basic", "client_secret_basic")]) },
			runtime: quiet,
		});
		await app.start();
		stop = () => app.stop(1000);
		const res = await fetch(`http://127.0.0.1:${app.get(listening).port()}/oauth/token`, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				authorization: basicOf("basic", "basic-secret"),
			},
			body: "grant_type=urn%3Atest%3Akept-out",
		});
		expect(res.status).toBe(503);
		expect(logged.lines().at(-1)).toEqual({
			level: "warn",
			event: "http.unavailable",
			fields: { what: "audit", route: "/oauth/token" },
		});
		expect(JSON.stringify(logged.lines().at(-1))).not.toContain("kept-out");
	});

	it("dispatches to a grant contributed from outside, for the clients whose allowance lists it", async () => {
		const extra = defineModule({ name: "extra-grant", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client }) => ({ kind: "issued", body: { echo: client.id } }),
			})),
		]);
		const post = await serve([extra], { clients: [echoClients.echo()] });
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).body).toEqual({ echo: "echo" });
		expect((await post({ grant_type: "urn:test:echo" }, "basic")).body.error).toBe(
			"unauthorized_client",
		);
	});

	it("admits and issues through the issuance policies under the grant type and the session, answering a refusal from admits or from issue as invalid_grant, auditing the policy but no value", async () => {
		const asked: IssuanceRequest[] = [];
		const policed = defineModule({ name: "policed", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, param, admits, issue }) => {
					const subject = param("subject") ?? "s";
					const session = param("session");
					const from = session === undefined ? {} : { session };
					const grant = { subject, issuedTo: client.id, audience: ["https://api"], scope: [] };
					const admitted = await admits(grant, from);
					if (admitted.kind === "refused") return admitted;
					const issued = await issue(grant, { ...from, notAfter: 1_800_000_060_000 });
					if (issued.kind === "refused") return issued;
					return {
						kind: "issued",
						body: { token_type: issued.access.tokenType, expires_in: issued.access.expiresIn },
					};
				},
			})),
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					asked.push(request);
					// "late" is admitted, then refused when issued.
					const late = asked.filter(({ grant }) => grant.subject === "late").length === 2;
					return request.grant.subject === "unwelcome" || late
						? { kind: "refused", reason: "test_reason", description: "not for this subject" }
						: { kind: "allowed" };
				},
			})),
		]);
		const post = await serve([policed], { clients: [echoClients.echo()] });
		const issued = await post({ grant_type: "urn:test:echo", session: "sid" }, "echo");
		expect([issued.status, issued.body]).toEqual([200, { token_type: "Bearer", expires_in: 60 }]);
		expect(asked.map(({ grantType, session }) => ({ grantType, session }))).toEqual([
			{ grantType: "urn:test:echo", session: "sid" },
			{ grantType: "urn:test:echo", session: "sid" },
		]);
		const refusal = [400, { error: "invalid_grant", error_description: "not for this subject" }];
		for (const subject of ["unwelcome", "late"]) {
			const before = events.length;
			const refused = await post({ grant_type: "urn:test:echo", subject }, "echo");
			expect([refused.status, refused.body]).toEqual(refusal);
			expect(events.slice(before)).toEqual([
				{
					kind: "token.issued.failure",
					at: 1_800_000_000_000,
					attributes: {
						client: "echo",
						source: "127.0.0.1",
						grant_type: "urn:test:echo",
						reason: "issuance_refused",
						error: "invalid_grant",
						policy: "test-policy",
						refusal: "test_reason",
					},
				},
			]);
		}
		expect(asked.map(({ grant }) => grant.subject)).toEqual([
			"s",
			"s",
			"unwelcome",
			"late",
			"late",
		]);
		expect(JSON.stringify(events)).not.toMatch(/unwelcome|late|not for this subject/);
	});

	it("tells the issuance policies an issuance continues a grant only when the grant says so", async () => {
		const seen: unknown[] = [];
		const continuing = defineModule({ name: "continuing", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, param, admits, issue }) => {
					const from = param("continuing") === "yes" ? { continuing: true as const } : {};
					const grant = { subject: "s", issuedTo: client.id, audience: ["https://api"], scope: [] };
					const admitted = await admits(grant, from);
					if (admitted.kind === "refused") return admitted;
					const issued = await issue(grant, from);
					if (issued.kind === "refused") return issued;
					return { kind: "issued", body: {} };
				},
			})),
			m.contribute(issuancePolicies).by(() => ({
				name: "watching",
				judge: async (request) => {
					seen.push(request.continuing);
					return { kind: "allowed" };
				},
			})),
		]);
		const post = await serve([continuing], { clients: [echoClients.echo()] });
		expect((await post({ grant_type: "urn:test:echo", continuing: "yes" }, "echo")).status).toBe(
			200,
		);
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		expect(seen).toEqual([true, true, undefined, undefined]);
	});

	it("issues for the lifetime a grant gives in place of tokens' own", async () => {
		const longer = defineModule({ name: "longer", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, issue }) => {
					const grant = { subject: "s", issuedTo: client.id, audience: ["https://api"], scope: [] };
					const issued = await issue(grant, { lifetimeSeconds: 7200 });
					if (issued.kind === "refused") return issued;
					return { kind: "issued", body: { expires_in: issued.access.expiresIn } };
				},
			})),
		]);
		const post = await serve([longer], { clients: [echoClients.echo()] });
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).body).toEqual({
			expires_in: 7200,
		});
	});

	it("tells each session issuance of a token issued from a session before the grant answers, and one that fails answers no token", async () => {
		const told: unknown[] = [];
		const echo = defineModule({ name: "echo", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, param, issue }) => {
					const session = param("session");
					const grant = { subject: "s", issuedTo: client.id, audience: ["https://api"], scope: [] };
					const issued = await issue(grant, session === undefined ? {} : { session });
					if (issued.kind === "refused") return issued;
					told.push("answered");
					return { kind: "issued", body: { id: issued.access.id } };
				},
			})),
			...["first", "second"].map((name) =>
				m.contribute(sessionIssuances).by(() => ({
					issued: async (session, access) => {
						if (session === "failing") throw new Unavailable("test");
						told.push({ name, session, access });
					},
				})),
			),
		]);
		const post = await serve([echo], { clients: [echoClients.echo()] });
		const { id } = (await post({ grant_type: "urn:test:echo", session: "sid" }, "echo")).body;
		const access = { id, expiresAt: 1_800_003_600_000 };
		expect(told).toEqual([
			{ name: "first", session: "sid", access },
			{ name: "second", session: "sid", access },
			"answered",
		]);
		told.length = 0;
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).status).toBe(200);
		expect(told).toEqual(["answered"]);
		told.length = 0;
		const failed = await post({ grant_type: "urn:test:echo", session: "failing" }, "echo");
		expect([failed.status, failed.body]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(told).toEqual([]);
	});

	it("issues client credentials through the issuance policies", async () => {
		const asked: IssuanceRequest[] = [];
		const refusing = defineModule({ name: "refusing", takes: [] }, (m) => [
			m.contribute(issuancePolicies).by(() => ({
				name: "test-policy",
				judge: async (request) => {
					asked.push(request);
					return { kind: "refused", reason: "test_reason", description: "not for clients" };
				},
			})),
		]);
		const post = await serve([refusing]);
		const refused = await post({ grant_type: "client_credentials" }, "basic");
		expect([refused.status, refused.body]).toEqual([
			400,
			{ error: "invalid_grant", error_description: "not for clients" },
		]);
		expect(asked).toEqual([
			{
				grant: { subject: "basic", issuedTo: "basic", audience: ["https://api"], scope: ["read"] },
				grantType: "client_credentials",
			},
		]);
	});

	it("refuses an authentication time far ahead of the clock as invalid_grant, by tokens' own rule", async () => {
		const ahead = defineModule({ name: "ahead", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ client, param, issue }) => {
					const grant = {
						subject: "s",
						issuedTo: client.id,
						audience: ["https://api"],
						scope: [],
						authenticatedAt: 1_800_000_000_000 + Number(param("ahead")),
					};
					const issued = await issue(grant);
					return issued.kind === "refused" ? issued : { kind: "issued", body: {} };
				},
			})),
		]);
		const post = await serve([ahead], { clients: [echoClients.echo()] });
		expect((await post({ grant_type: "urn:test:echo", ahead: "300000" }, "echo")).status).toBe(200);
		const refused = await post({ grant_type: "urn:test:echo", ahead: "300001" }, "echo");
		expect([refused.status, refused.body.error]).toEqual([400, "invalid_grant"]);
		expect(events.at(-1)?.attributes).toMatchObject({
			policy: "tokens",
			reason: "issuance_refused",
		});
	});

	it("tells where it answers, on the public origin whatever path the issuer has", async () => {
		const at = async (origin: string) => {
			const app = await assemble({
				modules: endpointModules(clientAllowanceModule, rateLimitStandIn, auditStandIn().module),
				config: {
					...endpointConfig({ peer: { "public-origin": origin }, issuer: `${origin}/tenant` }),
				},
				runtime: quiet,
			});
			return app.get(tokenEndpointLocation).url;
		};
		expect(await at("https://as.example")).toBe("https://as.example/oauth/token");
	});

	it("answers an error code a grant owns as 400, as the grant names it", async () => {
		const polled = defineModule({ name: "polled", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ param }) => ({ kind: "error", error: param("answer") ?? "" }),
			})),
		]);
		const post = await serve([polled], { clients: [echoClients.echo()] });
		for (const answer of ["authorization_pending", "slow_down", "owned_by_the_grant"]) {
			const res = await post({ grant_type: "urn:test:echo", answer }, "echo");
			expect([res.status, res.body.error]).toEqual([400, answer]);
		}
	});

	it("answers a grant's error with its status and members, never letting members replace the error [rfc6749-5.2-d]", async () => {
		const owned = defineModule({ name: "owned", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ param }) =>
					param("answer") === "none"
						? {
								kind: "error",
								error: "unauthorized",
								status: 401,
								members: { error_description: "\u0001" },
							}
						: {
								kind: "error",
								error: "invalid_grant",
								description: 'stronger "login" needed',
								members: { step_up: ["mfa"], error: "other", error_description: "other" },
							},
			})),
		]);
		const post = await serve([owned], { clients: [echoClients.echo()] });
		const none = await post({ grant_type: "urn:test:echo", answer: "none" }, "echo");
		expect([none.status, none.body]).toEqual([401, { error: "unauthorized" }]);
		const stepUp = await post({ grant_type: "urn:test:echo" }, "echo");
		expect([stepUp.status, stepUp.body]).toEqual([
			400,
			// A description holds printable ASCII but `"` and `\` (RFC 6749 §5.2).
			{ step_up: ["mfa"], error: "invalid_grant", error_description: "stronger ?login? needed" },
		]);
		expect(events.map((e) => e.attributes?.error)).toEqual(["unauthorized", "invalid_grant"]);
	});

	it("challenges a grant's 401 with the client's method, or with every method when it has none", async () => {
		const unauthorized = defineModule({ name: "unauthorized", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ param }) => ({
					kind: "error",
					error: "invalid_client",
					status: param("status") === "400" ? 400 : 401,
				}),
			})),
		]);
		const post = await serve([unauthorized], {
			clients: [echoClients.echo(), echoClients.pubecho()],
		});
		const echo = { grant_type: "urn:test:echo" };
		const challenge = async (form: Record<string, string>, id?: string) => {
			const res = await post(form, id);
			return [res.status, res.headers.get("www-authenticate")];
		};
		expect(await challenge(echo, "echo")).toEqual([401, 'Basic realm="client"']);
		expect(await challenge({ ...echo, client_id: "pubecho" })).toEqual([
			401,
			'Basic realm="client"',
		]);
		expect(await challenge({ ...echo, status: "400" }, "echo")).toEqual([400, null]);
	});

	it("drops what a grant's error may not carry: a success's or the error's members, an error_uri that is not a printable URI, a status but 400 or 401 [rfc6749-5.2-e] [rfc6749-5.2-a]", async () => {
		const loose = defineModule({ name: "loose", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				bodies: ["json"],
				handle: async ({ value }) => ({
					kind: "error",
					error: String(value("error")),
					status: value("status") as 400,
					members: value("members") as Record<string, unknown>,
				}),
			})),
		]);
		const post = await serve([loose], { clients: [echoClients.echo()] });
		const answered = async (error: string, members: Record<string, unknown>, status?: number) => {
			const res = await post({ grant_type: "urn:test:echo", error, members, status }, "echo", {
				as: "json",
			});
			return [res.status, res.body];
		};
		const success = {
			access_token: "t",
			token_type: "Bearer",
			expires_in: 1,
			refresh_token: "r",
			scope: "read",
		};
		const own = { error: "other", error_description: "other" };
		expect(await answered("invalid_grant", { ...success, ...own, kept: 1 })).toEqual([
			400,
			{ kept: 1, error: "invalid_grant" },
		]);
		for (const uri of [
			"https://e.example/a b",
			'https://e.example/"',
			"https://e.example/\u00e9",
			"doc",
			1,
		]) {
			expect(await answered("invalid_grant", { error_uri: uri })).toEqual([
				400,
				{ error: "invalid_grant" },
			]);
		}
		const uri = "https://e.example/doc?x=1#y";
		expect(await answered("invalid_grant", { error_uri: uri })).toEqual([
			400,
			{ error_uri: uri, error: "invalid_grant" },
		]);
		expect((await answered("invalid_grant", {}, 200))[0]).toBe(400);
		expect((await answered("invalid_grant", {}, 503))[0]).toBe(400);
		expect((await answered("invalid_client", {}, 500))[0]).toBe(401);
	});

	it("takes a JSON body only for a grant that declares it, and a form only for one that does; another type is 415, and an empty form names no grant", async () => {
		const declared = defineModule({ name: "declared", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				bodies: ["json"],
				handle: async ({ param, value }) => ({
					kind: "issued",
					body: { scope: param("scope") ?? null, assertion: value("assertion") ?? null },
				}),
			})),
		]);
		const post = await serve([declared], { clients: [echoClients.echo()] });
		const echo = { grant_type: "urn:test:echo", scope: "read", assertion: { id: "a", n: [1] } };
		const json = await post(echo, "echo", { as: "json" });
		expect([json.status, json.body]).toEqual([
			200,
			{ scope: "read", assertion: { id: "a", n: [1] } },
		]);
		const form = await post({ grant_type: "urn:test:echo", scope: "read" }, "echo");
		expect([form.status, form.body.error]).toEqual([400, "invalid_request"]);
		const cc = await post({ grant_type: "client_credentials" }, "basic", { as: "json" });
		expect([cc.status, cc.body.error]).toEqual([400, "invalid_request"]);
		// After the JSON grant's issuance, each body a grant does not take is a refusal recorded.
		expect(events.slice(1).map((e) => e.attributes)).toEqual([
			{
				client: "echo",
				source: "127.0.0.1",
				grant_type: "urn:test:echo",
				reason: "unsupported_body",
				error: "invalid_request",
			},
			{
				client: "basic",
				source: "127.0.0.1",
				grant_type: "client_credentials",
				reason: "unsupported_body",
				error: "invalid_request",
			},
		]);
		const text = await post({ grant_type: "client_credentials" }, "basic", { as: "text" });
		expect(text.status).toBe(415);
		// An empty form is checked as any other, and names no grant_type.
		expect((await post({}, "basic")).body.error_description).toBe("grant_type is required");
	});

	it("gives a grant that takes both bodies each one's values, a form's as single strings [rfc6749-3.2-d]", async () => {
		const both = defineModule({ name: "both", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				bodies: ["form", "json"],
				handle: async ({ param, value }) => ({
					kind: "issued",
					body: {
						n: param("n") ?? null,
						value: value("n") ?? null,
						absent: value("x") ?? null,
					},
				}),
			})),
		]);
		const post = await serve([both], { clients: [echoClients.echo()] });
		const form = await post({ grant_type: "urn:test:echo", n: "1" }, "echo");
		expect(form.body).toEqual({ n: "1", value: "1", absent: null });
		const json = await post({ grant_type: "urn:test:echo", n: 1 }, "echo", { as: "json" });
		expect(json.body).toEqual({ n: null, value: 1, absent: null });
		const repeated = await post(new URLSearchParams("grant_type=urn:test:echo&n=1&n=2"), "echo");
		expect([repeated.status, repeated.body.error]).toEqual([400, "invalid_request"]);
	});

	it("refuses an OAuth parameter sent in JSON as other than a string for every grant, null being left out", async () => {
		const echoing = (grantType: string, bodies: Grant["bodies"]): Grant => ({
			grantType,
			readsAmbient: "none",
			...(bodies ? { bodies } : {}),
			handle: async ({ param, value }) => ({
				kind: "issued",
				body: { scope: param("scope") ?? null, assertion: value("assertion") ?? null },
			}),
		});
		const echoes = defineModule({ name: "echoes", takes: [] }, (m) => [
			m.contribute(grants).by(() => echoing("urn:test:echo", ["json"])),
			m.contribute(grants).by(() => echoing("urn:test:other", ["form", "json"])),
		]);
		const post = await serve([echoes], { clients: [echoClients.echoes()] });
		const mistyped = [
			["scope", ["admin"]],
			["code", 1],
			["redirect_uri", { uri: "https://app.example/cb" }],
			["refresh_token", ["a", "b"]],
			["audience", ["https://api"]],
			["resource", true],
			["subject_token", 0],
			["client_secret", false],
		] as const;
		for (const grantType of ["urn:test:echo", "urn:test:other"]) {
			const sent = (members: Record<string, unknown>) =>
				post({ grant_type: grantType, ...members }, "echoes", { as: "json" });
			for (const [name, given] of mistyped) {
				const res = await sent({ [name]: given });
				expect([name, res.status, res.body.error]).toEqual([name, 400, "invalid_request"]);
			}
			const left = await sent({ scope: null, assertion: { id: "a" } });
			expect([left.status, left.body]).toEqual([200, { scope: null, assertion: { id: "a" } }]);
		}
		const typed = await post({ grant_type: ["urn:test:echo"] }, "echoes", { as: "json" });
		expect([typed.status, typed.body.error]).toEqual([400, "invalid_request"]);
		const reasons = events.filter((e) => e.kind === "token.issued.failure");
		expect(new Set(reasons.map((e) => e.attributes?.reason))).toEqual(
			new Set(["mistyped_parameter"]),
		);
		// A mistyped client_secret is refused by client authentication before this check.
		const authenticated = mistyped.filter(([name]) => name !== "client_secret");
		expect(reasons).toHaveLength(authenticated.length * 2 + 1);
	});

	it("gives a grant the binding its tokens carry, and none when the request has none", async () => {
		const echo = defineModule({ name: "echo-binding", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async ({ binding }) => ({ kind: "issued", body: { binding: binding ?? null } }),
			})),
			m.contribute(senderBindings).by(() => ({
				member: "test",
				tokenType: "Test",
				read: async (request) =>
					request.form.has("bind") ? { kind: "bound", confirmation: "k1" } : { kind: "absent" },
			})),
		]);
		const post = await serve([echo], { clients: [echoClients.echo()] });
		expect((await post({ grant_type: "urn:test:echo", bind: "1" }, "echo")).body.binding).toEqual({
			member: "test",
			confirmation: "k1",
			tokenType: "Test",
		});
		expect((await post({ grant_type: "urn:test:echo" }, "echo")).body.binding).toBeNull();
	});
});
