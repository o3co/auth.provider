import { generateKeyPairSync } from "node:crypto";
import { httpConfig } from "@mod/http/testing";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { accessTokenSigning } from "@mod/keys";
import { keysConfig } from "@mod/keys/testing";
import { expect, it } from "vitest";
import { composedModules } from "../../../test/composed.ts";
import { revokedInMemory } from "../../../test/revoked.ts";
import { type AccessGrant, tokens } from "../../contract.ts";

let now = 1_800_000_000_400;
const runtime = quietRuntime({ clock: { now: () => now } });
const privateKey = generateKeyPairSync("ed25519")
	.privateKey.export({ format: "pem", type: "pkcs8" })
	.toString();
const grant: AccessGrant = { subject: "s", issuedTo: "c", audience: ["api"], scope: [] };
const payloadOf = (token: string) =>
	JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString());

async function boot() {
	const app = await assemble({
		modules: [...composedModules, revokedInMemory(() => runtime.clock.now()).module],
		config: {
			...kernelConfig(),
			...httpConfig({}),
			...keysConfig({ signing: { kid: "k", alg: "EdDSA", "private-key": privateKey } }),
			...issuerConfig({ url: "https://issuer.example" }),
			tokens: {
				"subject-check": "none",
				revocation: "unsupported",
				"access-token-lifetime": "60s",
			},
		},
		runtime,
	});
	return { t: app.get(tokens), signer: app.get(accessTokenSigning) };
}

it("writes a grant's standing time as o3co_standing_at, whole seconds floored and never after iat, and none without one", async () => {
	const { t } = await boot();
	const issue = async (given: AccessGrant) => {
		const issued = await t.issue({ grant: given, grantType: "test" });
		if (issued.kind !== "issued") throw new Error("refused");
		return payloadOf(issued.access.token);
	};
	const iat = Math.floor(now / 1000);
	expect(await issue(grant)).not.toHaveProperty("o3co_standing_at");
	expect((await issue({ ...grant, standingAt: now - 5_900 })).o3co_standing_at).toBe(
		Math.floor((now - 5_900) / 1000),
	);
	expect((await issue({ ...grant, standingAt: now + 60_000 })).o3co_standing_at).toBe(iat);
	// A standing before the epoch, as a grant with no time of its own gives, is kept as it is.
	expect((await issue({ ...grant, standingAt: -30_000 })).o3co_standing_at).toBe(-30);
	// It never moves the lifetime: exp runs from iat alone.
	const old = await issue({ ...grant, standingAt: now - 3_600_000 });
	expect(old.exp - old.iat).toBe(60);
});

it("reads a token's standing as its claim, else its iat, and refuses a claim that is no whole second up to iat as shape", async () => {
	const { t, signer } = await boot();
	const iat = Math.floor(now / 1000);
	const signedWith = (extra: object) =>
		signer.sign({
			iss: "https://issuer.example",
			sub: "s",
			aud: "api",
			client_id: "c",
			iat,
			exp: iat + 60,
			jti: "j",
			...extra,
		});
	const standingOf = async (extra: object) => {
		const read = await t.verifyAccess(await signedWith(extra));
		return read.kind === "valid" ? read.standingAt : read.reason;
	};
	expect(await standingOf({})).toBe(iat * 1000);
	expect(await standingOf({ o3co_standing_at: iat - 10 })).toBe((iat - 10) * 1000);
	// keys signs no null claim, so a present null never reaches tokens; any other shape is refused.
	for (const claim of ["1", 1.5, iat + 1, true, {}]) {
		expect(await standingOf({ o3co_standing_at: claim }), JSON.stringify(claim)).toBe("shape");
	}
	now += 1;
});
