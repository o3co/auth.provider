import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { accessTokenSigning, keys } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import senderBindingModule from "@mod/sender-binding/module";
import { describe, expect, it } from "vitest";
import { type AccessGrant, tokens } from "../src/contract.ts";
import tokensModule from "../src/module.ts";
import { revokedInMemory } from "./revoked.ts";

const now = 1_800_000_000_000;
const grant: AccessGrant = { subject: "s", issuedTo: "c", audience: ["api"], scope: [] };

async function boot(signing?: Module, at = now) {
	const app = await assemble({
		modules: [
			http,
			signing ?? keysModule,
			issuerModule,
			senderBindingModule,
			tokensModule,
			revokedInMemory(() => at).module,
		],
		config: {
			...kernelConfig(),
			...httpConfig({}),
			...(signing ? {} : keysConfig()),
			...issuerConfig({ url: "https://issuer.example" }),
			tokens: { "subject-check": "none", revocation: "unsupported" },
		},
		runtime: quietRuntime({ clock: { now: () => at } }),
	});
	return { t: app.get(tokens), access: app.get(accessTokenSigning) };
}

describe("access tokens, signed through accessTokenSigning", () => {
	it("are signed and verified there, never through keys' own sign and verify", async () => {
		// A ring of keys' own, apart: the stand-in hands on accessTokenSigning and refuses the rest.
		const ring = await assemble({
			modules: [http, keysModule],
			config: { ...kernelConfig(), ...httpConfig({}), ...keysConfig() },
			runtime: quietRuntime({ clock: { now: () => now } }),
		});
		const refused = async (): Promise<never> => {
			throw new TypeError("keys: an access token is signed through accessTokenSigning");
		};
		const standIn = defineModule({ name: "keys", replicaSafe: false, takes: [] }, (m) => [
			m.provide(keys).by(() => ({ ...ring.get(keys), sign: refused, verify: refused })),
			m.provide(accessTokenSigning).by(() => ring.get(accessTokenSigning)),
		]);
		const { t } = await boot(standIn);
		const issued = await t.issue({ grant, grantType: "test" });
		if (issued.kind !== "issued") throw new Error(issued.policy);
		const { token, id } = issued.access;
		expect(await t.verifyAccess(token)).toMatchObject({ kind: "valid", id });
	});
});

describe("an access token's iat", () => {
	const iat = Math.floor(now / 1000);
	const signed = async (access: Awaited<ReturnType<typeof boot>>["access"], times: object) =>
		access.sign({
			iss: "https://issuer.example",
			sub: "s",
			aud: "api",
			client_id: "c",
			jti: "j",
			...times,
		});
	const checked = async (times: object, at = now) => {
		const { t, access } = await boot(undefined, at);
		const answer = await t.verifyAccess(await signed(access, times));
		return answer.kind === "valid" ? "valid" : answer;
	};

	it("is refused as shape when exp comes before it", async () => {
		expect(await checked({ iat, exp: iat - 1 + 3600 })).toBe("valid");
		expect(await checked({ iat: iat + 30, exp: iat + 29 })).toEqual({
			kind: "invalid",
			reason: "shape",
		});
	});

	it("is taken up to 60 seconds ahead of the clock, and refused as shape past that", async () => {
		expect(await checked({ iat: iat + 60, exp: iat + 3600 })).toBe("valid");
		expect(await checked({ iat: iat + 61, exp: iat + 3600 })).toEqual({
			kind: "invalid",
			reason: "shape",
		});
	});

	it("takes an exp equal to its iat while that time is still ahead", async () => {
		expect(await checked({ iat: iat + 30, exp: iat + 30 })).toBe("valid");
	});

	it("is refused 60,001 ms ahead of the clock, to the millisecond", async () => {
		// A clock 999 ms into its second: an iat 61 s on from the second it is in lies 60,001 ms ahead.
		const at = now + 999;
		expect(await checked({ iat: iat + 61, exp: iat + 3600 }, at)).toEqual({
			kind: "invalid",
			reason: "shape",
		});
		expect(await checked({ iat: iat + 60, exp: iat + 3600 }, at)).toBe("valid");
	});

	it("is answered expired before shape where a token has both ended and times tokens never issues", async () => {
		expect(await checked({ iat: iat - 100, exp: iat - 200 })).toEqual({
			kind: "invalid",
			reason: "expired",
		});
	});

	it("is refused as shape where exp lies more than a day after it, as tokens never issues", async () => {
		expect(await checked({ iat, exp: iat + 86_400 })).toBe("valid");
		expect(await checked({ iat, exp: iat + 86_401 })).toEqual({ kind: "invalid", reason: "shape" });
		// Moving iat ahead stretches no lifetime: past 60 seconds it is refused, and within them the day holds.
		expect(await checked({ iat: iat + 60, exp: iat + 60 + 86_401 })).toEqual({
			kind: "invalid",
			reason: "shape",
		});
	});
});
