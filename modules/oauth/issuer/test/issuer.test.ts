import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, type BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { issuer, type MetadataItem, metadata } from "../src/contract.ts";
import issuerModule from "../src/module.ts";
import { issuerConfig } from "../src/testing.ts";

const boot = (
	url: unknown,
	origin?: string,
	environment: "production" | "development" = "production",
) =>
	assemble({
		modules: [http, issuerModule],
		config: {
			...kernelConfig({ environment }),
			...httpConfig(
				origin
					? {
							"public-origin": origin,
							...(origin.startsWith("http:") ? { "insecure-origin": true } : {}),
						}
					: {},
			),
			issuer: { url },
		},
	});
const refusedAt = async (run: Promise<unknown>) =>
	((await run.catch((error) => error)) as BootRefused).refusals?.map((r) => r.where);

it("names this provider by the configured URL, as written, frozen", async () => {
	const app = await boot("https://issuer.example/tenant");
	expect(app.get(issuer).url).toBe("https://issuer.example/tenant");
	expect(Object.isFrozen(app.get(issuer))).toBe(true);
});

it("builds a test configuration on https://issuer.example by default", async () => {
	const built = await assemble({
		modules: [http, issuerModule],
		config: { ...kernelConfig(), ...httpConfig(), ...issuerConfig() },
	});
	expect(built.get(issuer).url).toBe("https://issuer.example");
});

it("refuses an issuer URL the section does not take, as written", async () => {
	const refused: Record<string, unknown> = {
		"another scheme": "ftp://issuer.example",
		"a trailing /": "https://issuer.example/",
		"not a URL": "not a url",
		missing: undefined,
		"a query": "https://issuer.example?tenant=a",
		"a fragment": "https://issuer.example#a",
		userinfo: "https://user@issuer.example",
		"an upper-case scheme": "HTTPS://issuer.example",
	};
	for (const [name, url] of Object.entries(refused)) {
		expect(await refusedAt(boot(url)), name).toEqual(["issuer.url"]);
	}
});

it("refuses an origin other than the public origin, and takes a path under it", async () => {
	expect(await refusedAt(boot("https://issuer.example", "https://other.example"))).toEqual([
		"issuer.url",
	]);
	expect((await boot("https://as.example/t", "https://as.example")).get(issuer).url).toBe(
		"https://as.example/t",
	);
});

it("collects the items this server names itself by, refusing two contributions of one item or one of the issuer item", async () => {
	const named = contract<readonly MetadataItem[]>("named");
	const item = (module: string, name: string, value: unknown) =>
		defineModule({ name: module, takes: [] }, (m) => [
			m.contribute(metadata).by(() => ({ name, value })),
		]);
	const reader = defineModule({ name: "reader", takes: [metadata] }, (m) => [
		m.provide(named).by((c) => c.collect(metadata)),
	]);
	const bootWith = (...modules: ReturnType<typeof item>[]) =>
		assemble({
			modules: [http, issuerModule, ...modules],
			config: { ...kernelConfig(), ...httpConfig(), ...issuerConfig() },
		});
	const app = await bootWith(
		item("a", "a_endpoint", "https://issuer.example/a"),
		item("b", "b", undefined),
		reader,
	);
	expect(app.get(named)).toEqual([
		{ name: "a_endpoint", value: "https://issuer.example/a" },
		{ name: "b", value: undefined },
	]);
	expect(await refusedAt(bootWith(item("a", "same", 1), item("b", "same", 2)))).toEqual([
		"issuer.metadata:same",
	]);
	// The issuer item is the configured URL, refused whether or not anyone reads the items.
	for (const value of ["https://elsewhere.example", undefined]) {
		expect(await refusedAt(bootWith(item("a", "issuer", value)))).toEqual([
			"issuer.metadata:issuer",
		]);
	}
});

it("takes all it names, with a public origin and without one", async () => {
	for (const origin of [{ "public-origin": "https://issuer.example" }, {}]) {
		const input = {
			modules: [http, issuerModule],
			config: { ...kernelConfig(), ...httpConfig(origin), ...issuerConfig() },
		};
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(input))["issuer"], JSON.stringify(origin)).toBeUndefined();
	}
});

it("takes a plain-http issuer only beside the same plain-http public origin, which http takes only when told", async () => {
	expect(await refusedAt(boot("http://issuer.example", undefined, "development"))).toEqual([
		"issuer.url",
	]);
	const plain = await boot("http://as.example", "http://as.example", "development");
	expect(plain.get(issuer).url).toBe("http://as.example");
});

it("refuses a plain-http issuer in a production deployment", async () => {
	const refused = await boot("http://as.example", "http://as.example").catch(
		(error: BootRefused) => error.refusals,
	);
	expect(refused).toContainEqual({
		where: "issuer.url",
		reason:
			"is plain http, which a production deployment does not take; set kernel.environment = development to try one",
	});
});
