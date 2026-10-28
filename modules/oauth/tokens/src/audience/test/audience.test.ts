import { generateKeyPairSync } from "node:crypto";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { accessTokenSigning } from "@mod/keys";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import senderBindingModule from "@mod/sender-binding/module";
import { describe, expect, it } from "vitest";
import { revokedInMemory } from "../../../test/revoked.ts";
import { type AccessGrant, audienceAdditions, tokens } from "../../contract.ts";
import tokensModule from "../../module.ts";

const runtime = quietRuntime();
const privateKey = generateKeyPairSync("ed25519")
	.privateKey.export({ format: "pem", type: "pkcs8" })
	.toString();
const issuer = "https://issuer.example";
const grant: AccessGrant = { subject: "s", issuedTo: "c", audience: ["api"], scope: ["x"] };
const payloadOf = (t: string) =>
	JSON.parse(Buffer.from(t.split(".")[1] ?? "", "base64url").toString());

/** A module adding the issuer to the audience of every grant whose scope holds `x`. */
const addsIssuer = defineModule({ name: "adds-issuer", takes: [] }, (m) => [
	m.contribute(audienceAdditions).by(() => ({
		name: "issuer",
		added: (g) => (g.scope.includes("x") ? [issuer] : []),
	})),
]);

async function boot() {
	const app = await assemble({
		modules: [
			http,
			keysModule,
			issuerModule,
			senderBindingModule,
			tokensModule,
			revokedInMemory(() => runtime.clock.now()).module,
			addsIssuer,
		],
		config: {
			...kernelConfig(),
			...httpConfig({}),
			...keysConfig({ signing: { kid: "k", alg: "EdDSA", "private-key": privateKey } }),
			...issuerConfig({ url: issuer }),
			tokens: { "subject-check": "none", revocation: "unsupported" },
		},
		runtime,
	});
	return { t: app.get(tokens), signer: app.get(accessTokenSigning) };
}

const issued = async (t: Awaited<ReturnType<typeof boot>>["t"], g: AccessGrant) => {
	const answer = await t.issue({ grant: g, grantType: "test" });
	if (answer.kind !== "issued") throw new Error(answer.policy);
	return answer.access.token;
};

describe("audiences an access token is for besides its grant's", () => {
	it("writes them after the grant's audience, counted in aud_added, reads them back apart, and carries none on", async () => {
		const { t } = await boot();
		const token = await issued(t, grant);
		expect(payloadOf(token)).toMatchObject({ aud: ["api", issuer], aud_added: 1 });
		const checked = await t.verifyAccess(token);
		if (checked.kind !== "valid") throw new Error(checked.reason);
		expect(checked.grant.audience).toEqual(["api"]);
		expect(checked.addedAudience).toEqual([issuer]);
		// Issued again from the grant read back, as a refresh or an exchange does, for a scope the
		// addition does not answer: none of what was added comes with it.
		const again = await issued(t, { ...checked.grant, scope: [] });
		expect(payloadOf(again).aud).toBe("api");
	});

	it("adds none the grant's audience already holds, which reads back whole", async () => {
		const { t } = await boot();
		const token = await issued(t, { ...grant, audience: [issuer] });
		expect(payloadOf(token).aud).toBe(issuer);
		expect(payloadOf(token).aud_added).toBeUndefined();
		const checked = await t.verifyAccess(token);
		if (checked.kind !== "valid") throw new Error(checked.reason);
		expect(checked.grant.audience).toEqual([issuer]);
		expect(checked.addedAudience).toBeUndefined();
	});

	it("refuses an aud_added that is not a positive whole number, or would leave the grant no audience", async () => {
		const { t, signer } = await boot();
		const iat = Math.floor(runtime.clock.now() / 1000);
		const base = { iss: issuer, sub: "s", client_id: "c", iat, exp: iat + 60, jti: "j" };
		const both = (aud_added: unknown) => ({ aud: ["api", issuer], aud_added });
		const malformed = [...[0, -1, 1.5, "1", 2].map(both), { aud: issuer, aud_added: 1 }];
		for (const extra of malformed) {
			const checked = await t.verifyAccess(await signer.sign({ ...base, ...extra }));
			expect(checked, JSON.stringify(extra)).toEqual({ kind: "invalid", reason: "shape" });
		}
	});
});
