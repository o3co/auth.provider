import type { HttpRequest } from "@mod/http";
import { testRequest } from "@mod/http/testing";
import { assemble, defineModule, isUnavailable, kernelConfig, type Module } from "@mod/kernel";
import secretHashModule from "@mod/secret-hash/module";
import { testBcryptHash, testScryptHash } from "@mod/secret-hash/testing";
import { expect, it, vi } from "vitest";
import { type ClientRecord, type Clients, clientSources, clients } from "../src/contract.ts";
import clientsModule from "../src/module.ts";
import { basic, refusalsOf } from "./parts.ts";

// Counts the scrypt runs inside secret-hash; the tests' hashes come from scryptSync, which is not counted.
const counted = vi.hoisted(() => ({ scrypt: 0 }));
vi.mock("node:crypto", async (original) => {
	const real = await original<typeof import("node:crypto")>();
	return {
		...real,
		scrypt: (...args: Parameters<typeof real.scrypt>) => {
			counted.scrypt++;
			return (real.scrypt as (...a: unknown[]) => void)(...args);
		},
	};
});

const confidential = (id: string, method: string, hash: string) => ({
	id,
	kind: "confidential",
	method,
	sections: { "client-secret": { hash } },
});

async function boot(list: unknown[], extra: readonly Module[] = []): Promise<Clients> {
	const app = await assemble({
		modules: [clientsModule, secretHashModule, ...extra],
		config: { ...kernelConfig(), clients: { registered: list } },
	});
	return app.get(clients);
}

const basicRequest = (id: string, secret: string): HttpRequest =>
	testRequest({ method: "POST", headers: new Map(Object.entries(basic(id, secret))) });
const post = (id: string, secret: string): HttpRequest =>
	testRequest({
		method: "POST",
		form: new Map([
			["client_id", [id]],
			["client_secret", [secret]],
		]),
	});
const as = (id: string) => ({ kind: "authenticated", client: { id } });
const refused = (reason: string) => ({ kind: "refused", reason });

it("authenticates basic and post clients holding a bcrypt or a scrypt hash of their secret", async () => {
	const c = await boot([
		confidential("b-basic", "client_secret_basic", testBcryptHash("b-secret")),
		confidential("b-post", "client_secret_post", testBcryptHash("b-secret")),
		confidential("s-basic", "client_secret_basic", testScryptHash("s-secret")),
		confidential("s-post", "client_secret_post", testScryptHash("s-secret")),
	]);
	for (const [request, answer] of [
		[basicRequest("b-basic", "b-secret"), as("b-basic")],
		[post("b-post", "b-secret"), as("b-post")],
		[basicRequest("s-basic", "s-secret"), as("s-basic")],
		[post("s-post", "s-secret"), as("s-post")],
		[basicRequest("b-basic", "s-secret"), refused("bad_credentials")],
		[post("s-post", "b-secret"), refused("bad_credentials")],
	] as const) {
		expect(await c.authenticate(request)).toMatchObject(answer);
	}
});

it("checks secrets within its own assembly's secret-hash limit, whatever another assembly sets", async () => {
	const assembled = async (max: number) =>
		(
			await assemble({
				modules: [clientsModule, secretHashModule],
				config: {
					...kernelConfig(),
					clients: {
						registered: [confidential("b", "client_secret_basic", testBcryptHash("b-secret"))],
					},
					"secret-hash": { "max-concurrent": max },
				},
			})
		).get(clients);
	const one = await assembled(1);
	// Built after, with its own limit; the first keeps its one.
	await assembled(8);
	const first = one.authenticate(basicRequest("b", "b-secret"));
	await expect(one.authenticate(basicRequest("b", "b-secret"))).rejects.toSatisfy(isUnavailable);
	expect(await first).toMatchObject(as("b"));
});

it("refuses boot on a secret that is no bcrypt or scrypt hash, at its place and never by the client's id or the value", async () => {
	const list = [
		confidential("fine", "client_secret_basic", testScryptHash("x")),
		confidential("plain", "client_secret_post", "plain-text-secret-value"),
	];
	const refusals = await refusalsOf(boot(list));
	expect(refusals.map((r) => r.where)).toEqual(["clients.registered.1.sections.client-secret"]);
	expect(JSON.stringify(refusals)).not.toMatch(/plain-text-secret-value|"plain"/);
});

it("refuses boot on a registered client whose method needs a secret and that holds no hash, at its place and never by its id", async () => {
	const list = [
		{ id: "pub", kind: "public", method: "none" },
		{ id: "bare", kind: "confidential", method: "client_secret_basic" },
		{
			id: "empty",
			kind: "confidential",
			method: "client_secret_post",
			sections: { "client-secret": {} },
		},
		// An empty hash is one that does not read, refused once.
		confidential("blank", "client_secret_post", ""),
	];
	const refusals = await refusalsOf(boot(list));
	expect(refusals.map((r) => r.where)).toEqual([
		"clients.registered.1.sections.client-secret",
		"clients.registered.2.sections.client-secret",
		"clients.registered.3.sections.client-secret",
	]);
	expect(refusals[0]?.reason).toBe("its method needs a secret, and it holds no hash");
	expect(refusals[1]?.reason).toBe("its method needs a secret, and it holds no hash");
	expect(JSON.stringify(refusals)).not.toMatch(/bare|empty|blank/);
});

it("refuses a source's client whose secret is no hash, or that holds none, matching it by no form", async () => {
	const answers: Record<string, ClientRecord> = {
		remote: confidential("remote", "client_secret_post", "plain") as ClientRecord,
		bare: { id: "bare", kind: "confidential", method: "client_secret_post", sections: {} },
	};
	const source = defineModule({ name: "source" }, (m) => [
		m.contribute(clientSources).by(() => ({ find: async (id: string) => answers[id] })),
	]);
	const c = await boot([], [source]);
	expect(await c.authenticate(post("remote", "plain"))).toMatchObject(refused("bad_credentials"));
	expect(await c.authenticate(post("bare", "x"))).toMatchObject(refused("bad_credentials"));
});

it("computes one scrypt per work in use for a known client, and none for an unknown client, an invalid record, another method's client or another client_id", async () => {
	const invalid = { id: "invalid", kind: "confidential", method: "no-such-method" } as ClientRecord;
	const source = defineModule({ name: "source" }, (m) => [
		m.contribute(clientSources).by(() => ({
			find: async (id: string) => (id === "invalid" ? invalid : undefined),
		})),
	]);
	const c = await boot(
		[
			confidential("s10", "client_secret_basic", testScryptHash("p", 10)),
			confidential("s11", "client_secret_post", testScryptHash("p", 11)),
		],
		[source],
	);
	const besideOther = testRequest({
		method: "POST",
		headers: new Map(Object.entries(basic("s10", "p"))),
		form: new Map([["client_id", ["s11"]]]),
	});
	const cases: [request: HttpRequest, answer: object, scryptRuns: number][] = [
		[basicRequest("s10", "p"), as("s10"), 2],
		[basicRequest("s10", "wrong"), refused("bad_credentials"), 2],
		[post("s11", "p"), as("s11"), 2],
		[basicRequest("nobody", "p"), refused("unknown_client"), 0],
		[post("nobody", "p"), refused("unknown_client"), 0],
		[post("invalid", "p"), refused("invalid_record"), 0],
		[basicRequest("s11", "p"), refused("wrong_method"), 0],
		[besideOther, refused("bad_credentials"), 0],
	];
	for (const [request, answer, scryptRuns] of cases) {
		counted.scrypt = 0;
		expect(await c.authenticate(request)).toMatchObject(answer);
		expect(counted.scrypt).toBe(scryptRuns);
	}
});
