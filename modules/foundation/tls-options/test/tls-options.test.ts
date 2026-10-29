import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import { optionsOf, type TlsOptions, tlsOptions } from "../src/contract.ts";
import tlsOptionsModule from "../src/module.ts";
import { section } from "../src/section.ts";
import { handshakeWith, type Offer } from "../src/testing.ts";

// A client taking anything, its security level lowered, sees each peer offer what it says alone.
const anything = { minVersion: "TLSv1", ciphers: "ALL:@SECLEVEL=0" } as const;
const offers: readonly Offer[] = ["tls1.1", "static-rsa", "cbc", "ecdhe-aead", "tls1.3"];
/** Each peer's handshake under `options`: agreed, or refused by the handshake itself (never another failure). */
const kinds = async (options: TlsOptions) =>
	Object.fromEntries(
		await Promise.all(
			offers.map(async (offer) => {
				const met = await handshakeWith(options, offer);
				return [
					offer,
					met.kind === "refused" && /^ERR_SSL_/.test(met.code) ? "refused" : met.kind,
				] as const;
			}),
		),
	);

describe("the TLS peers a client's options are held against", () => {
	it("each offers the one version and suite it says", async () => {
		expect(await handshakeWith(anything, "tls1.1")).toMatchObject({ protocol: "TLSv1.1" });
		expect(await handshakeWith(anything, "static-rsa")).toMatchObject({
			protocol: "TLSv1.2",
			cipher: "AES128-GCM-SHA256",
		});
		expect(await handshakeWith(anything, "cbc")).toMatchObject({
			protocol: "TLSv1.2",
			cipher: "ECDHE-ECDSA-AES128-SHA256",
		});
		expect(await handshakeWith(anything, "ecdhe-aead")).toMatchObject({
			protocol: "TLSv1.2",
			cipher: "ECDHE-ECDSA-AES128-GCM-SHA256",
		});
		expect(await handshakeWith(anything, "tls1.3")).toMatchObject({ protocol: "TLSv1.3" });
	});

	it("refuses a client that offers no suite the peer takes", async () => {
		expect(await handshakeWith({ minVersion: "TLSv1.3" }, "ecdhe-aead")).toMatchObject({
			kind: "refused",
			code: expect.stringMatching(/^ERR_SSL_/),
		});
	});
});

describe("the section's options", () => {
	it("by default refuse an old TLS, the RSA key exchange and CBC, and take ECDHE with AEAD and TLS 1.3 [oidc-core-16.17-b] [oidc-core-16.17-c] [oidc-discovery-7.1-b] [oidc-discovery-7.1-c]", async () => {
		expect(await kinds(optionsOf(section.parse({})))).toEqual({
			"tls1.1": "refused",
			"static-rsa": "refused",
			cbc: "refused",
			"ecdhe-aead": "agreed",
			"tls1.3": "agreed",
		});
	});

	it("narrow as the operator writes them: TLS 1.3 alone, or fewer suites", async () => {
		const tls13 = optionsOf(section.parse({ "min-version": "TLSv1.3" }));
		expect(await kinds(tls13)).toMatchObject({ "ecdhe-aead": "refused", "tls1.3": "agreed" });
		const chacha = optionsOf(
			section.parse({ suites: ["TLS_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305"] }),
		);
		expect(await kinds(chacha)).toMatchObject({ "ecdhe-aead": "refused", "tls1.3": "agreed" });
		// TLS 1.3 alone refuses a TLS 1.2 peer in its handshake.
		const only13 = optionsOf(
			section.parse({ "min-version": "TLSv1.3", suites: ["TLS_AES_128_GCM_SHA256"] }),
		);
		expect(await handshakeWith(only13, "ecdhe-aead")).toMatchObject({
			kind: "refused",
			code: expect.stringMatching(/^ERR_SSL_/),
		});
	});

	it("are made from a section alone: no other code can write one", () => {
		// @ts-expect-error A weaker floor written by hand is no TlsOptions.
		const written: TlsOptions = { minVersion: "TLSv1.2", ciphers: "ALL:@SECLEVEL=0" };
		expect(written).toBeDefined();
	});

	it.each([
		["a version below TLS 1.2", { "min-version": "TLSv1.1" }, "min-version"],
		["the RSA key exchange", { suites: ["AES128-GCM-SHA256"] }, "suites.0"],
		["a CBC suite", { suites: ["ECDHE-RSA-AES128-SHA"] }, "suites.0"],
		["no suite", { suites: [] }, "suites"],
		[
			"a suite named twice",
			{ suites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"] },
			"suites",
		],
	])("refuse %s", (_, given, at) => {
		const read = section.safeParse(given);
		expect(read.error?.issues.map((issue) => issue.path.join("."))).toContain(at);
	});

	it.each([
		[
			"TLS 1.2's suites alone",
			{ suites: ["ECDHE-RSA-AES128-GCM-SHA256"] },
			["name a TLS 1.3 suite"],
		],
		[
			"TLS 1.3's suites alone while TLS 1.2 is taken",
			{ suites: ["TLS_AES_128_GCM_SHA256"] },
			["name a TLS 1.2 suite, or set min-version to TLSv1.3"],
		],
		[
			"no TLS 1.3 suite with TLS 1.3 alone",
			{ "min-version": "TLSv1.3", suites: ["ECDHE-RSA-AES128-GCM-SHA256"] },
			["name a TLS 1.3 suite"],
		],
	])("refuse %s, saying how to fix it", (_, given, said) => {
		const read = section.safeParse(given);
		expect(read.error?.issues.map((issue) => [issue.path.join("."), issue.message])).toEqual(
			said.map((message) => ["suites", message]),
		);
	});
});

it("gives its options frozen, as its section reads them", async () => {
	const got = contract<TlsOptions>("test.tls-options");
	const app = await assemble({
		modules: [
			tlsOptionsModule,
			defineModule({ name: "test-taker", takes: [tlsOptions], replicaSafe: true }, (m) => [
				m.provide(got).by((c) => c.get(tlsOptions)),
			]),
		],
		config: { ...kernelConfig(), "tls-options": { "min-version": "TLSv1.3" } },
		runtime: quietRuntime(),
	});
	const given = app.get(got);
	expect(given).toEqual(optionsOf(section.parse({ "min-version": "TLSv1.3" })));
	expect(Object.isFrozen(given)).toBe(true);
});
