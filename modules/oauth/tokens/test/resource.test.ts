import { testRequest } from "@mod/http/testing";
import { assemble, defineModule } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { senderBinding, senderBindings } from "@mod/sender-binding";
import { expect, it } from "vitest";
import { tokens } from "../src/contract.ts";
import { tokensConfig } from "../src/testing.ts";
import { composedConfig, composedModules, issueFor } from "./composed.ts";
import { revokedInMemory } from "./revoked.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });
const grant = { subject: "s", issuedTo: "c", audience: ["api"], scope: ["read"] };

/** A kind proving the key named in a header. */
const keyed = defineModule({ name: "keyed", replicaSafe: true, takes: [] }, (m) => [
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
		modules: [...composedModules, keyed, revokedInMemory(() => now).module],
		config: {
			...composedConfig(),
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
