import { assemble, BootRefused, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { outbound } from "@mod/outbound";
import outboundModule from "@mod/outbound/module";
import { expect, it } from "vitest";
import { externalJwt } from "../src/contract.ts";
import externalJwtModule from "../src/module.ts";
import { testSigner } from "../src/testing.ts";

it("offers verifiers to a composition with outbound, knowing the asymmetric algorithms only", async () => {
	const app = await assemble({
		modules: [outboundModule, externalJwtModule],
		config: { ...kernelConfig(), outbound: {} },
	});
	const jwt = app.get(externalJwt);
	expect([...jwt.algorithms].sort()).toEqual(
		[
			"EdDSA",
			"ES256",
			"ES384",
			"ES512",
			"PS256",
			"PS384",
			"PS512",
			"RS256",
			"RS384",
			"RS512",
		].sort(),
	);
	const signer = await testSigner("EdDSA");
	const token = await signer.sign({ exp: Math.floor(Date.now() / 1000) + 60 });
	const verified = await jwt
		.verifierOf({ inline: [signer.jwk] }, { algorithms: jwt.algorithms, skewMs: 0 })
		.verify(token);
	expect(verified.kind).toBe("valid");
});

/** A composition over a key set whose source can go down, on a clock the test moves. */
async function composed(section: Record<string, unknown> | undefined) {
	const signer = await testSigner("EdDSA", "k1");
	let now = 1_800_000_000_000;
	let up = true;
	const fake = defineModule({ name: "fake-outbound" }, (m) => [
		m.provide(outbound).by(() => ({
			fetch: async () => {
				if (!up) throw new Unavailable("outbound");
				return {
					status: 200,
					headers: new Map(),
					body: new TextEncoder().encode(JSON.stringify({ keys: [signer.jwk] })),
				};
			},
		})),
	]);
	const app = await assemble({
		modules: [fake, externalJwtModule],
		config: { ...kernelConfig(), ...(section ? { "external-jwt": section } : {}) },
		runtime: quietRuntime({
			clock: { now: () => now },
			random: { bytes: (n: number) => new Uint8Array(n) },
		}),
	});
	const verifier = app
		.get(externalJwt)
		.verifierOf(
			{ jwks: { url: "https://issuer.example/jwks", hosts: ["issuer.example"] } },
			{ algorithms: ["EdDSA"], skewMs: 0 },
		);
	return {
		checked: async () =>
			(await verifier.verify(await signer.sign({ exp: Math.floor(now / 1000) + 60 }))).kind,
		/** The source goes down and the clock moves on. */
		downFor: (ms: number) => {
			up = false;
			now += ms;
		},
	};
}

it("uses a set it cannot renew for a day by default", async () => {
	const set = await composed(undefined);
	expect(await set.checked()).toBe("valid");
	set.downFor(86_399_000);
	expect(await set.checked()).toBe("valid");
	set.downFor(1_000);
	expect(await set.checked()).toBe("unavailable");
});

it("uses a set it cannot renew as long as the operator's section says", async () => {
	const set = await composed({ "key-set-max-age-ms": 7_200_000 });
	expect(await set.checked()).toBe("valid");
	set.downFor(7_199_000);
	expect(await set.checked()).toBe("valid");
	set.downFor(1_000);
	expect(await set.checked()).toBe("unavailable");
});

it("refuses a section outside its bounds", async () => {
	for (const refused of [
		{ "key-set-max-age-ms": 3_599_999 },
		{ "key-set-max-age-ms": 2_592_000_001 },
		{ "key-set-max-age-ms": 3_600_000.5 },
		{ "key-set-max-age": 7_200_000 },
	]) {
		await expect(
			assemble({
				modules: [outboundModule, externalJwtModule],
				config: { ...kernelConfig(), outbound: {}, "external-jwt": refused },
			}),
			JSON.stringify(refused),
		).rejects.toBeInstanceOf(BootRefused);
	}
});
