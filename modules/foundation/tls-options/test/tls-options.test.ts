import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { afterEach, describe, expect, it, vi } from "vitest";
import { heldToFloor, isFloor, type TlsOptions, tlsOptions } from "../src/contract.ts";
import tlsOptionsModule from "../src/module.ts";
import { section } from "../src/section.ts";
import { type Handshake, handshakeWith, type Offer, tlsOptionsFor } from "../src/testing.ts";

// A client taking anything, its security level lowered, sees each peer offer what it says alone.
const anything = { minVersion: "TLSv1", ciphers: "ALL:@SECLEVEL=0" } as const;
const offers: readonly Offer[] = ["tls1.1", "static-rsa", "cbc", "ecdhe-aead", "tls1.3"];
/**
 * What a handshake came to, a refusal named by the codes both sides gave: a version, or no suite in
 * common. A reset or an early close is neither, and reads as itself.
 */
function outcomeOf(met: Handshake): string {
	if (met.kind === "agreed") return "agreed";
	// The client's side by its alert's number (RFC 8446 §6), which no OpenSSL build names otherwise.
	const { alert, peerCode } = met;
	if (alert === 70 && peerCode === "ERR_SSL_UNSUPPORTED_PROTOCOL") return "refused: version";
	if (alert === 40 && peerCode === "ERR_SSL_NO_SHARED_CIPHER") return "refused: suite";
	return `other: ${met.code} (alert ${alert}) / ${peerCode}`;
}
/** Each peer's handshake under a client held to `floor`. */
const kinds = async (floor: TlsOptions) =>
	Object.fromEntries(
		await Promise.all(
			offers.map(
				async (offer) =>
					[offer, outcomeOf(await handshakeWith(heldToFloor(floor, {}), offer))] as const,
			),
		),
	);
/** The suites the section takes by default, as a floor names them. */
const defaultSuites = section.parse({}).suites.join(":");

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
		expect(await kinds(tlsOptionsFor({}))).toEqual({
			"tls1.1": "refused: version",
			"static-rsa": "refused: suite",
			cbc: "refused: suite",
			"ecdhe-aead": "agreed",
			"tls1.3": "agreed",
		});
	});

	it("narrow as the operator writes them: TLS 1.3 alone, or fewer suites", async () => {
		const tls13 = tlsOptionsFor({ "min-version": "TLSv1.3" });
		expect(await kinds(tls13)).toMatchObject({
			"ecdhe-aead": "refused: version",
			"tls1.3": "agreed",
		});
		const chacha = tlsOptionsFor({
			suites: ["TLS_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305"],
		});
		expect(await kinds(chacha)).toMatchObject({
			"ecdhe-aead": "refused: suite",
			"tls1.3": "agreed",
		});
		// TLS 1.3 alone refuses a TLS 1.2 peer in its handshake.
		const only13 = tlsOptionsFor({ "min-version": "TLSv1.3", suites: ["TLS_AES_128_GCM_SHA256"] });
		expect(outcomeOf(await handshakeWith(heldToFloor(only13, {}), "ecdhe-aead"))).toBe(
			"refused: version",
		);
	});

	it("are a floor only as tls-options made them: a spread, an assigned copy, a cast or a frozen value written elsewhere is none", () => {
		// @ts-expect-error A weaker floor written by hand is no TlsOptions.
		const written: TlsOptions = { minVersion: "TLSv1.2", ciphers: "ALL:@SECLEVEL=0" };
		const made = tlsOptionsFor({});
		const spread: TlsOptions = { ...made, ...{ ciphers: "ALL:@SECLEVEL=0" } };
		const assigned: TlsOptions = Object.assign({}, made, { minVersion: "TLSv1.1" });
		const cast = { minVersion: "TLSv1.2", ciphers: defaultSuites } as unknown as TlsOptions;
		const frozen = Object.freeze({ minVersion: "TLSv1.2", ciphers: defaultSuites });
		expect([made, written, spread, assigned, cast, frozen].map(isFloor)).toEqual([
			true,
			false,
			false,
			false,
			false,
			false,
		]);
		expect(Object.keys(made)).toEqual(["minVersion", "ciphers", "rejectUnauthorized"]);
	});

	it("hold a caller's options to the floor, its own keys last over whatever the caller passed", () => {
		const floor = tlsOptionsFor({});
		const loosened = {
			minVersion: "TLSv1",
			ciphers: "ALL:@SECLEVEL=0",
			rejectUnauthorized: false,
			ca: "the caller's authority",
		} as const;
		expect(heldToFloor(floor, loosened)).toEqual({
			ca: "the caller's authority",
			minVersion: "TLSv1.2",
			ciphers: defaultSuites,
			rejectUnauthorized: true,
		});
		// Nor any key that would take the connection past the floor, whatever its value.
		for (const key of [
			"secureContext",
			"secureProtocol",
			"secureOptions",
			"checkServerIdentity",
			"pskCallback",
		]) {
			expect(() => heldToFloor(floor, { [key]: undefined }), key).toThrow(
				`options held to the TLS floor take none of ${key}, which would loosen it`,
			);
		}
		// Nor one that options hide from a first look and show to a later one, as a Proxy may: what is
		// checked is what is given.
		let looked = 0;
		const shifting = new Proxy(
			{},
			{
				ownKeys: () => ["checkServerIdentity"],
				getOwnPropertyDescriptor: () =>
					looked++ === 0
						? undefined
						: { value: () => undefined, enumerable: true, configurable: true },
			},
		);
		expect(Object.hasOwn(heldToFloor(floor, shifting), "checkServerIdentity")).toBe(false);
		// What it gives is the caller's options, no floor; a floor copied by hand is refused.
		expect(isFloor(heldToFloor(floor, {}))).toBe(false);
		const copied = { ...floor } as TlsOptions;
		expect(() => heldToFloor(copied, {})).toThrow(TypeError);
	});

	it("check the peer's certificate where NODE_TLS_REJECT_UNAUTHORIZED is 0, which bare options do not [oidc-core-16.17-a] [oidc-discovery-7.1-a]", async () => {
		vi.stubEnv("NODE_TLS_REJECT_UNAUTHORIZED", "0");
		const held = heldToFloor(tlsOptionsFor({}), {});
		expect(await handshakeWith({}, "tls1.3", false)).toMatchObject({ kind: "agreed" });
		expect(await handshakeWith(held, "tls1.3", false)).toMatchObject({
			kind: "refused",
			code: "DEPTH_ZERO_SELF_SIGNED_CERT",
		});
		// The caller's own authority is still believed.
		expect(await handshakeWith(held, "tls1.3")).toMatchObject({ kind: "agreed" });
	});

	it("are no floor where an older tls-options made them, without the certificate check", () => {
		// As tls-options made a floor before it carried `rejectUnauthorized`: marked and frozen, its keys then.
		const older = { minVersion: "TLSv1.2", ciphers: defaultSuites };
		Object.defineProperty(older, Symbol.for("@mod/tls-options.floor"), {
			value: true,
			enumerable: false,
		});
		Object.freeze(older);
		expect(isFloor(older)).toBe(false);
		expect(() => heldToFloor(older as unknown as TlsOptions, {})).toThrow(TypeError);
	});

	it("are no floor where a key is inherited, hidden or behind a getter, as a spread would not copy it", () => {
		const marked = (floor: object) => {
			Object.defineProperty(floor, Symbol.for("@mod/tls-options.floor"), { value: true });
			return Object.freeze(floor);
		};
		const keys = { minVersion: "TLSv1.2", ciphers: defaultSuites };
		const inherited = marked(Object.assign(Object.create({ rejectUnauthorized: true }), keys));
		const hidden = marked(
			Object.defineProperty({ ...keys }, "rejectUnauthorized", { value: true, enumerable: false }),
		);
		let asked = 0;
		const getter = marked(
			Object.defineProperty({ ...keys }, "rejectUnauthorized", {
				get: () => asked++ === 0,
				enumerable: true,
			}),
		);
		expect([inherited, hidden, getter].map(isFloor)).toEqual([false, false, false]);
		expect(isFloor(marked({ ...keys, rejectUnauthorized: true }))).toBe(true);
	});

	it("are a floor however many copies of the package are loaded", async () => {
		vi.resetModules();
		const another = await import("../src/testing.ts");
		const fromAnother = another.tlsOptionsFor({});
		expect(isFloor(fromAnother)).toBe(true);
	});

	it.each([
		["a version below TLS 1.2", { "min-version": "TLSv1.1" }, "min-version"],
		["the RSA key exchange", { suites: ["AES128-GCM-SHA256"] }, "suites.0"],
		["a CBC suite", { suites: ["ECDHE-RSA-AES128-SHA"] }, "suites.0"],
		["no suite", { suites: [] }, "suites"],
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
		[
			"a suite named twice",
			{
				suites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"],
			},
			["names each suite once"],
		],
	])("refuse %s, saying how to fix it", (_, given, said) => {
		const read = section.safeParse(given);
		expect(read.error?.issues.map((issue) => [issue.path.join("."), issue.message])).toEqual(
			said.map((message) => ["suites", message]),
		);
	});
});

afterEach(() => vi.unstubAllEnvs());

it("warns at every boot where NODE_TLS_REJECT_UNAUTHORIZED is 0, naming the variable alone", async () => {
	const warned = async (value: string) => {
		vi.stubEnv("NODE_TLS_REJECT_UNAUTHORIZED", value);
		const recording = recordingLog();
		await assemble({
			modules: [tlsOptionsModule],
			config: kernelConfig(),
			runtime: quietRuntime({ log: recording.log }),
		});
		return recording.lines().filter((line) => line.event.startsWith("tls-options."));
	};
	expect(await warned("0")).toEqual([
		{
			level: "warn",
			event: "tls-options.reject_unauthorized_ignored",
			fields: {
				variable: "NODE_TLS_REJECT_UNAUTHORIZED",
				reason:
					"the provider's own connections check certificates; trust a private authority by NODE_EXTRA_CA_CERTS",
			},
		},
	]);
	expect(await warned("1")).toEqual([]);
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
	expect(given).toEqual(tlsOptionsFor({ "min-version": "TLSv1.3" }));
	expect(isFloor(given)).toBe(true);
	expect(Object.isFrozen(given)).toBe(true);
});
