import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientSecret, clientsConfig, confidentialClient } from "@mod/clients/testing";
import { type Grant, grants, sessionIssuances, targetRules } from "@mod/grants";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	isUnavailable,
	kernelConfig,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import { senderBindings } from "@mod/sender-binding";
import { type IssuanceRequest, issuancePolicies, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { afterEach, expect, it } from "vitest";
import { grantCaller, grantCalls, grantInput } from "../src/testing.ts";
import { basicOf, endpointConfig, endpointModules } from "./deployment.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
let stop = async () => {};
afterEach(() => stop());

/** A grant that records what it is handed, and issues once with a cap and a session. */
const recording = () => {
	const seen: unknown[] = [];
	const module = defineModule({ name: "recording" }, (m) => [
		m.contribute(grants).by(() => ({
			grantType: "urn:test:record",
			handle: async (input) => {
				seen.push({ client: input.client.id, x: input.param("x"), binding: input.binding });
				const grant = {
					subject: "s",
					issuedTo: input.client.id,
					audience: ["https://api"],
					scope: [],
				};
				const admitted = await input.admits(grant, { session: "sid" });
				if (admitted.kind === "refused") return admitted;
				const issued = await input.issue(grant, { notAfter: 1_800_000_120_000, session: "sid" });
				if (issued.kind === "refused") return issued;
				const { expiresIn, tokenType } = issued.access;
				// No scope granted: the endpoint answers it by leaving scope out, whatever the grant writes.
				return {
					kind: "issued",
					body: { expires_in: expiresIn, token_type: tokenType, scope: "" },
				};
			},
		})),
	]);
	return { seen, module };
};
const configured = clientsConfig([
	confidentialClient({
		id: "rec",
		method: "client_secret_basic",
		sections: allowancesFor({ grants: ["urn:test:record"], audiences: ["https://api"] }),
	}),
]);

it("hands a grant what the token endpoint hands it, for the same client, parameters and binding", async () => {
	const real = recording();
	const app = await assemble({
		modules: endpointModules(
			clientAllowanceModule,
			rateLimitStandIn,
			auditStandIn().module,
			real.module,
			defineModule({ name: "binding" }, (m) => [
				m.contribute(senderBindings).by(() => ({
					member: "one",
					tokenType: "ONE",
					read: async (request) => {
						const value = request.headers.get("x-one");
						return value ? { kind: "bound", confirmation: value } : { kind: "absent" };
					},
				})),
			]),
		),
		config: { ...endpointConfig(), ...configured },
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const res = await fetch(`http://127.0.0.1:${app.get(listening).port()}/oauth/token`, {
		method: "POST",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			authorization: basicOf("rec", clientSecret("rec")),
			"x-one": "thumb",
		},
		body: new URLSearchParams({ grant_type: "urn:test:record", x: "1" }),
	});
	const throughEndpoint = await res.json();

	const harnessed = recording();
	const harness = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			harnessed.module,
		],
		config: { ...kernelConfig(), ...httpConfig(), ...configured },
		runtime,
	});
	const binding = { member: "one", confirmation: "thumb", tokenType: "ONE" };
	const outcome = await harness
		.get(grantCalls)
		.call("urn:test:record", "rec", { grant_type: "urn:test:record", x: "1" }, { binding });

	expect(harnessed.seen).toEqual(real.seen);
	expect(real.seen).toEqual([{ client: "rec", x: "1", binding }]);
	expect(outcome).toEqual({ kind: "issued", body: throughEndpoint });
	expect(throughEndpoint).toEqual({ expires_in: 120, token_type: "ONE" });
	expect(Object.keys(throughEndpoint as object)).not.toContain("scope");
});

it("hands a grant that takes JSON its members as the token endpoint does", async () => {
	const seen: unknown[] = [];
	const jsonGrant = () =>
		defineModule({ name: "json-grant" }, (m) => [
			m.contribute(grants).by(() => ({
				grantType: "urn:test:record",
				bodies: ["json"],
				handle: async ({ param, value }) => {
					seen.push({ scope: param("scope"), n: param("n"), assertion: value("assertion") });
					return { kind: "error", error: "invalid_grant" };
				},
			})),
		]);
	const params = { grant_type: "urn:test:record", scope: "read", n: 1, assertion: { id: "a" } };
	const app = await assemble({
		modules: endpointModules(
			clientAllowanceModule,
			rateLimitStandIn,
			auditStandIn().module,
			jsonGrant(),
		),
		config: { ...endpointConfig(), ...configured },
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	await fetch(`http://127.0.0.1:${app.get(listening).port()}/oauth/token`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: basicOf("rec", clientSecret("rec")),
		},
		body: JSON.stringify(params),
	});
	const harness = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			jsonGrant(),
		],
		config: { ...kernelConfig(), ...httpConfig(), ...configured },
		runtime,
	});
	await harness.get(grantCalls).call("urn:test:record", "rec", params);
	expect(seen).toEqual([
		{ scope: "read", n: undefined, assertion: { id: "a" } },
		{ scope: "read", n: undefined, assertion: { id: "a" } },
	]);
});

it("refuses an OAuth parameter sent in JSON as neither a string nor null before the grant runs, as the token endpoint does", async () => {
	let ran = 0;
	const grant = defineModule({ name: "json-grant" }, (m) => [
		m.contribute(grants).by(() => ({
			grantType: "urn:test:record",
			bodies: ["json"],
			handle: async () => {
				ran++;
				return { kind: "error", error: "invalid_grant" };
			},
		})),
	]);
	const harness = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			grant,
		],
		config: { ...kernelConfig(), ...httpConfig(), ...configured },
		runtime,
	});
	const call = (scope: unknown) =>
		harness
			.get(grantCalls)
			.call("urn:test:record", "rec", { grant_type: "urn:test:record", scope });
	expect(await call(7)).toEqual({
		kind: "error",
		error: "invalid_request",
		description: "scope must be a string",
	});
	expect(ran).toBe(0);
	expect(await call(null)).toEqual({ kind: "error", error: "invalid_grant" });
	expect(ran).toBe(1);
});

it("gives a test that calls a grant itself the input the harness hands the grant", async () => {
	const seen: unknown[] = [];
	const grant: Grant = {
		grantType: "urn:test:record",
		bodies: ["json"],
		handle: async (input) => {
			const { client, binding, request } = input;
			seen.push({ client: client.id, s: input.param("s"), n: input.value("n"), binding, request });
			return { kind: "error", error: "invalid_grant" };
		},
	};
	const harness = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			defineModule({ name: "direct" }, (m) => [m.contribute(grants).by(() => grant)]),
		],
		config: { ...kernelConfig(), ...httpConfig(), ...configured },
		runtime,
	});
	const binding = { member: "one", confirmation: "thumb", tokenType: "ONE" };
	const params = { grant_type: "urn:test:record", s: "x", n: 1 };
	await harness.get(grantCalls).call("urn:test:record", "rec", params, { binding });
	const client = await harness.get(clients).find("rec");
	if (!client) throw new Error("no client");
	await grant.handle(grantInput(harness.get(tokens), grant, client, params, { binding }));
	expect(seen).toHaveLength(2);
	expect(seen[1]).toEqual(seen[0]);
	// A request of the test's own replaces only the request; the parameters read as given.
	const own = testRequest();
	const input = grantInput(harness.get(tokens), grant, client, params, { request: own });
	expect([input.request, input.param("s")]).toEqual([own, "x"]);
});

it("answers a refusal of the issuance policies as the token endpoint does, asked under the grant type and session", async () => {
	const asked: IssuanceRequest[] = [];
	const refusing = defineModule({ name: "refusing" }, (m) => [
		m.contribute(issuancePolicies).by(() => ({
			name: "test-policy",
			judge: async (request) => {
				asked.push(request);
				return { kind: "refused", reason: "test_reason", description: "refused here" };
			},
		})),
	]);
	const harness = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			recording().module,
			refusing,
		],
		config: { ...kernelConfig(), ...httpConfig(), ...configured },
		runtime,
	});
	const outcome = await harness.get(grantCalls).call("urn:test:record", "rec", {});
	expect(outcome).toEqual({ kind: "error", error: "invalid_grant", description: "refused here" });
	expect(asked).toEqual([
		{
			grant: { subject: "s", issuedTo: "rec", audience: ["https://api"], scope: [] },
			grantType: "urn:test:record",
			session: "sid",
		},
	]);
});

it("tells each session issuance of a token issued from a session, and one that fails revokes the token and throws on", async () => {
	const told: unknown[] = [];
	let failing = false;
	const telling = defineModule({ name: "telling" }, (m) => [
		m.contribute(sessionIssuances).by(() => ({
			issued: async (session, access) => {
				told.push({ session, access });
				if (failing) throw new Unavailable("test");
			},
		})),
	]);
	const harness = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			recording().module,
			telling,
		],
		config: { ...kernelConfig(), ...httpConfig(), ...configured },
		runtime,
	});
	const calls = harness.get(grantCalls);
	expect(await calls.call("urn:test:record", "rec", {})).toMatchObject({ kind: "issued" });
	failing = true;
	const thrown = await calls.call("urn:test:record", "rec", {}).catch((error) => error);
	expect(isUnavailable(thrown)).toBe(true);
	expect(told).toEqual([
		{ session: "sid", access: { id: expect.any(String), expiresAt: 1_800_000_120_000 } },
		{ session: "sid", access: { id: expect.any(String), expiresAt: 1_800_000_120_000 } },
	]);
	const [kept, revoked] = told.map(
		(t) => `stand-in.${(t as { access: { id: string } }).access.id}`,
	);
	expect((await harness.get(tokens).verifyAccess(kept as string)).kind).toBe("valid");
	expect(await harness.get(tokens).verifyAccess(revoked as string)).toEqual({
		kind: "invalid",
		reason: "revoked",
	});
});

it("refuses to boot with two rules for a request's audience, as the token endpoint does", async () => {
	const rule = (name: string) =>
		defineModule({ name }, (m) => [
			m.contribute(targetRules).by(() => ({
				target: ({ audience }) => ({ kind: "audience", audience }),
			})),
		]);
	await expect(
		assemble({
			modules: [
				http,
				clientsModule,
				secretHashModule,
				tokensStandIn(),
				grantCaller,
				clientAllowanceModule,
				rule("one"),
				rule("two"),
			],
			config: { ...kernelConfig(), ...httpConfig(), ...configured },
			runtime,
		}),
	).rejects.toSatisfy(
		(error) =>
			error instanceof BootRefused && JSON.stringify(error.refusals).includes("target-rules"),
	);
});

it("refuses an audience asked of a grant that takes none before the grant runs, as the token endpoint does", async () => {
	const handled: string[] = [];
	const twoGrants = defineModule({ name: "two-grants" }, (m) => [
		m.contribute(grants).by(() => ({
			grantType: "urn:test:record",
			handle: async () => {
				handled.push("untargeted");
				return { kind: "issued", body: {} };
			},
		})),
		m.contribute(grants).by(() => ({
			grantType: "urn:test:targeted",
			targets: true,
			handle: async () => {
				handled.push("targeted");
				return { kind: "issued", body: {} };
			},
		})),
	]);
	const strict = defineModule({ name: "strict" }, (m) => [
		m.contribute(targetRules).by(() => ({
			target: ({ audience }) => ({ kind: "audience", audience }),
			untargeted: ({ param }) =>
				param("resource")
					? { kind: "error", error: "invalid_target", description: "no resource here" }
					: undefined,
		})),
	]);
	const app = await assemble({
		modules: [
			http,
			clientsModule,
			secretHashModule,
			tokensStandIn(),
			grantCaller,
			clientAllowanceModule,
			twoGrants,
			strict,
		],
		config: { ...kernelConfig(), ...httpConfig(), ...configured },
		runtime,
	});
	const calls = app.get(grantCalls);
	expect(await calls.call("urn:test:record", "rec", { resource: "https://api" })).toEqual({
		kind: "error",
		error: "invalid_target",
		description: "no resource here",
	});
	expect(await calls.call("urn:test:record", "rec", {})).toEqual({ kind: "issued", body: {} });
	expect(await calls.call("urn:test:targeted", "rec", { resource: "https://api" })).toEqual({
		kind: "issued",
		body: {},
	});
	expect(handled).toEqual(["untargeted", "targeted"]);
});
