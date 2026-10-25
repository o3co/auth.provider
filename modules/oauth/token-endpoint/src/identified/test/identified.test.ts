import { type AuditEvent, audit } from "@mod/audit";
import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { authMethods, clientSources } from "@mod/clients";
import clientEvents from "@mod/clients/audit-events";
import { clientsConfig, confidentialClient, publicClient } from "@mod/clients/testing";
import { grants } from "@mod/grants";
import { listening } from "@mod/http";
import { assemble, defineModule, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import { simulatedStore } from "@mod/store/testing";
import { afterEach, describe, expect, it } from "vitest";
import { basicOf, endpointConfig, endpointModules } from "../../../test/deployment.ts";
import declared from "../../audit-events.ts";

const quiet = quietRuntime({
	clock: { now: () => 1_800_000_000_000 },
	random: { bytes: (n) => new Uint8Array(n).fill(1) },
});
/** A client allowed these grants: confidential with its method, or public with `none`. */
const client = (
	id: string,
	method: string,
	allowed: readonly string[],
	more: Record<string, unknown> = {},
) => {
	const sections = { ...allowancesFor({ grants: [...allowed], scopes: ["read"] }), ...more };
	return method === "none"
		? publicClient({ id, sections })
		: confidentialClient({ id, method, sections });
};

let stop = async () => {};
afterEach(() => stop());
/** The audit events of the latest `serve`. */
let events: readonly AuditEvent[] = [];
// Every event a test records is one the modules declare, with attributes they declare.
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

/** The endpoint with `extra` modules and these clients; posts a form as client `id` by Basic. */
async function serve(extra: Module[], clients: ReturnType<typeof client>[]) {
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
			...endpointConfig({ issuer: "https://issuer.example" }),
			...clientsConfig(clients),
		},
		runtime: quiet,
	});
	await app.start();
	stop = () => app.stop(1000);
	const url = `http://127.0.0.1:${app.get(listening).port()}/oauth/token`;
	const post = async (form: Record<string, string>, id: string, secret = `${id}-secret`) => {
		const res = await fetch(url, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				authorization: basicOf(id, secret),
			},
			body: String(new URLSearchParams(form)),
		});
		return {
			status: res.status,
			headers: res.headers,
			body: JSON.parse((await res.text()) || "{}") as Record<string, unknown>,
		};
	};
	return Object.assign(post, { url });
}

describe("a request naming no client", () => {
	const asserted = ["urn:test:assert"];
	/** A grant whose assertion names the client it is for: `as:<id>`, or a refusal. */
	const identifying = (seen: { identify: number; handled: unknown[] }) =>
		defineModule({ name: "identifying", takes: [] }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:assert",
				readsAmbient: "none",
				identify: async ({ param }) => {
					seen.identify++;
					const assertion = param("assertion") ?? "";
					if (assertion === "challenged") return { kind: "error", error: "invalid_client" };
					if (!assertion.startsWith("as:"))
						return { kind: "error", error: "invalid_grant", description: "untrusted signer" };
					return { kind: "client", client: assertion.slice(3), identified: { by: assertion } };
				},
				handle: async ({ client, identified }) => {
					seen.handled.push(identified);
					return { kind: "issued", body: { client: client.id, identified: identified ?? null } };
				},
			})),
			m.contribute(grants).by(() => ({
				grantType: "urn:test:echo",
				readsAmbient: "none",
				handle: async () => ({ kind: "issued", body: {} }),
			})),
		]);
	/** A method that reads a key header, so a public client may hold a key. */
	const keyed = defineModule({ name: "keyed", takes: [] }, (m) => [
		m.contribute(authMethods).by(() => ({
			name: "test-key",
			claimed: (r) => r.headers.get("x-test-key") ?? undefined,
			verify: async () => true,
		})),
	]);
	/** A source naming a public client with no credentials: one the operator did not register. */
	const sourced = defineModule({ name: "sourced", takes: [] }, (m) => [
		m.contribute(clientSources).by(() => ({
			find: async (id: string) =>
				id === "sourced" ? client("sourced", "none", asserted) : undefined,
		})),
	]);
	const serving = async () => {
		const seen = { identify: 0, handled: [] as unknown[] };
		const post = await serve(
			[identifying(seen), keyed, sourced],
			[
				client("agents", "none", asserted),
				client("ungranted", "none", []),
				client("mustbind", "none", asserted, { "sender-binding": { required: true } }),
				client("conf", "client_secret_basic", asserted),
				{ ...client("secretpub", "client_secret_basic", asserted), kind: "public" },
				// A public client that holds a key, by a method that reads one.
				{ ...client("keypub", "none", asserted), method: "test-key" },
			],
		);
		/** Posts the form with these headers and no client credentials but what they carry. */
		const raw = async (
			form: Record<string, string> | URLSearchParams,
			headers: Record<string, string> = {},
		) => {
			const res = await fetch(post.url, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
				body: String(new URLSearchParams(form as URLSearchParams)),
			});
			return {
				status: res.status,
				challenge: res.headers.get("www-authenticate"),
				body: JSON.parse((await res.text()) || "{}") as Record<string, unknown>,
			};
		};
		return { post, raw, seen };
	};
	const assert = (assertion: string) => ({ grant_type: "urn:test:assert", assertion });

	it("runs a grant that identifies the client for it, as for one that authenticated, handing back what it identified", async () => {
		const { raw, seen } = await serving();
		const done = await raw(assert("as:agents"));
		expect([done.status, done.body]).toEqual([
			200,
			{ client: "agents", identified: { by: "as:agents" } },
		]);
		expect(seen.identify).toBe(1);
		const at = quiet.clock.now();
		expect(events).toEqual([
			{
				kind: "token.issued",
				at,
				attributes: {
					client: "agents",
					source: "127.0.0.1",
					grant_type: "urn:test:assert",
					identified: "grant",
				},
			},
		]);
	});

	it("checks the identified client's allowance and binding as an authenticated one's, before the grant runs", async () => {
		const { raw, seen } = await serving();
		const ungranted = await raw(assert("as:ungranted"));
		expect([ungranted.status, ungranted.body.error]).toEqual([400, "unauthorized_client"]);
		const unbound = await raw(assert("as:mustbind"));
		expect([unbound.status, unbound.body.error]).toEqual([400, "invalid_request"]);
		expect(seen.handled).toEqual([]);
		expect(events.map((e) => e.attributes)).toEqual([
			{
				client: "ungranted",
				source: "127.0.0.1",
				grant_type: "urn:test:assert",
				identified: "grant",
				reason: "grant_type_not_allowed",
				error: "unauthorized_client",
			},
			{
				client: "mustbind",
				source: "127.0.0.1",
				grant_type: "urn:test:assert",
				identified: "grant",
				reason: "binding_required",
				error: "invalid_request",
			},
		]);
	});

	it("answers the grant's refusal to identify, recorded with no client and no failed authentication", async () => {
		const { raw } = await serving();
		const refused = await raw(assert("forged"));
		expect([refused.status, refused.body]).toEqual([
			400,
			{ error: "invalid_grant", error_description: "untrusted signer" },
		]);
		const challenged = await raw(assert("challenged"));
		expect([challenged.status, challenged.body.error, challenged.challenge]).toEqual([
			401,
			"invalid_client",
			'Basic realm="client"',
		]);
		expect(events.map((e) => [e.kind, e.attributes])).toEqual([
			[
				"token.issued.failure",
				{
					source: "127.0.0.1",
					grant_type: "urn:test:assert",
					identified: "grant",
					reason: "client_not_identified",
					error: "invalid_grant",
				},
			],
			[
				"token.issued.failure",
				{
					source: "127.0.0.1",
					grant_type: "urn:test:assert",
					identified: "grant",
					reason: "client_not_identified",
					error: "invalid_client",
				},
			],
		]);
	});

	it("is unavailable when the identified client is not one registered with no credentials", async () => {
		const { raw, seen } = await serving();
		for (const id of ["ghost", "sourced", "conf", "secretpub", "keypub"]) {
			const answered = await raw(assert(`as:${id}`));
			expect([answered.status, answered.body.error], id).toEqual([503, "temporarily_unavailable"]);
		}
		expect(seen.handled).toEqual([]);
		expect(events).toEqual([]);
	});

	it("checks repeated and mistyped parameters on the way, as for any request", async () => {
		const { post, raw, seen } = await serving();
		const twice = new URLSearchParams([
			["grant_type", "urn:test:assert"],
			["assertion", "as:agents"],
			["scope", "a"],
			["scope", "b"],
		]);
		const repeated = await raw(twice);
		expect([repeated.status, repeated.body.error]).toEqual([400, "invalid_request"]);
		const res = await fetch(post.url, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ ...assert("as:agents"), scope: 1 }),
		});
		expect([res.status, ((await res.json()) as { error: string }).error]).toEqual([
			400,
			"invalid_request",
		]);
		expect(seen.identify).toBe(0);
		expect(events.map((e) => e.attributes?.reason)).toEqual([
			"repeated_parameter",
			"mistyped_parameter",
		]);
		expect(
			events.every(
				(e) => e.attributes?.identified === "grant" && !("client" in (e.attributes ?? {})),
			),
		).toBe(true);
	});

	it("answers as today a request that carries anything a client authenticates with, or names no grant that can identify", async () => {
		const { raw, seen } = await serving();
		const unidentified = async (
			form: Record<string, string>,
			headers: Record<string, string> = {},
		) => {
			const answered = await raw(form, headers);
			return [answered.status, answered.body.error];
		};
		const today = [401, "invalid_client"];
		expect(await unidentified(assert("as:agents"), { authorization: "Bearer abc" })).toEqual(today);
		expect(await unidentified({ ...assert("as:agents"), client_id: "" })).toEqual(today);
		// No client assertion method is composed: its parameters are still credentials sent.
		expect(
			await unidentified({
				...assert("as:agents"),
				client_assertion: "x.y.z",
				client_assertion_type: "t",
			}),
		).toEqual(today);
		expect(await unidentified({ grant_type: "urn:test:echo" })).toEqual(today);
		expect(await unidentified({ assertion: "as:agents" })).toEqual(today);
		expect(await unidentified({ grant_type: "urn:test:none" })).toEqual(today);
		const both = new URLSearchParams([
			["grant_type", "urn:test:assert"],
			["grant_type", "urn:test:assert"],
			["assertion", "as:agents"],
		]);
		expect((await raw(both)).status).toBe(401);
		expect(seen.identify).toBe(0);
		expect(new Set(events.map((e) => e.kind))).toEqual(new Set(["client.authentication.failure"]));
		expect(events).toHaveLength(7);
	});

	it("keeps today's answers for clients that authenticate, or fail to, where a grant can identify", async () => {
		const { post, raw, seen } = await serving();
		const asConf = await post(assert("as:agents"), "conf");
		expect([asConf.status, asConf.body]).toEqual([200, { client: "conf", identified: null }]);
		const asPublic = await raw({ ...assert("as:agents"), client_id: "agents" });
		expect([asPublic.status, asPublic.body]).toEqual([200, { client: "agents", identified: null }]);
		const wrong = await post(assert("as:agents"), "conf", "nope");
		expect([wrong.status, wrong.body.error, wrong.headers.get("www-authenticate")]).toEqual([
			401,
			"invalid_client",
			'Basic realm="client"',
		]);
		const malformed = await raw(assert("as:agents"), { authorization: "Basic !!" });
		expect([malformed.status, malformed.body]).toEqual([
			400,
			{ error: "invalid_request", error_description: "malformed client credentials" },
		]);
		const twoMethods = await raw(
			{ ...assert("as:agents"), client_id: "conf", client_secret: "conf-secret" },
			{ authorization: basicOf("conf", "conf-secret") },
		);
		expect([twoMethods.status, twoMethods.body]).toEqual([
			400,
			{ error: "invalid_request", error_description: "use one client authentication method" },
		]);
		expect(seen.identify).toBe(0);
		expect(
			events
				.filter((e) => e.kind === "client.authentication.failure")
				.map((e) => e.attributes?.reason),
		).toEqual(["bad_credentials", "malformed_credentials", "multiple_methods"]);
		expect(events.some((e) => "identified" in (e.attributes ?? {}))).toBe(false);
	});
});
