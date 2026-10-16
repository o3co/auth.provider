import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import { senderBinding, senderBindings } from "@mod/sender-binding";
import senderBindingModule from "@mod/sender-binding/module";
import { expect, it } from "vitest";
import { type AccessGrant, type IssueLimits, type Tokens, tokens } from "../src/contract.ts";
import tokensModule from "../src/module.ts";
import { tokensConfig } from "../src/testing.ts";
import { revokedInMemory } from "./revoked.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });
const grant = { subject: "s", issuedTo: "c", audience: ["api"], scope: ["read"] };

/** Issues through `issue`, which nothing here refuses, and answers what it issued. */
async function issueFor(t: Tokens, grant: AccessGrant, limits?: IssueLimits) {
	const issued = await t.issue({ grant, grantType: "test" }, limits);
	if (issued.kind !== "issued") throw new Error(`refused by ${issued.policy}`);
	return issued.access;
}

/** A kind proving the key named in a header. */
const keyed = defineModule({ name: "keyed" }, (m) => [
	m.contribute(senderBindings).by(() => ({
		member: "jkt",
		tokenType: "DPoP",
		read: async (request) => {
			const key = request.headers.get("x-key");
			return key ? { kind: "bound", confirmation: key } : { kind: "absent" };
		},
	})),
]);

it("is the validity sender-binding admits a request by at a resource", async () => {
	const app = await assemble({
		modules: [
			http,
			keysModule,
			issuerModule,
			senderBindingModule,
			tokensModule,
			keyed,
			revokedInMemory(() => now).module,
		],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...keysConfig(),
			...issuerConfig(),
			...tokensConfig({ revocation: "denylist" }),
		},
		runtime,
	});
	const t = app.get(tokens);
	const admitted = (headers: Record<string, string>) =>
		app.get(senderBinding).admitted(testRequest({ headers: new Map(Object.entries(headers)) }), t);
	const plain = (await issueFor(t, grant)).token;
	const binding = { member: "jkt", confirmation: "k1", tokenType: "DPoP" };
	const bound = (await issueFor(t, grant, { binding })).token;

	const access = await admitted({ authorization: `Bearer ${plain}` });
	expect(access.kind === "admitted" && access.access.grant).toEqual(grant);
	const held = await admitted({ authorization: `DPoP ${bound}`, "x-key": "k1" });
	expect(held.kind === "admitted" && held.access.binding).toEqual(binding);
	expect(await admitted({ authorization: `DPoP ${bound}`, "x-key": "k2" })).toMatchObject({
		status: 401,
		error: "invalid_token",
	});
	await t.revokeAccess(plain);
	expect(await admitted({ authorization: `Bearer ${plain}` })).toMatchObject({
		status: 401,
		error: "invalid_token",
	});
});
