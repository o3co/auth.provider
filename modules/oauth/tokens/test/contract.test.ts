import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { type Assembly, assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import { senderBindings } from "@mod/sender-binding";
import senderBindingModule from "@mod/sender-binding/module";
import { expect, it } from "vitest";
import {
	type AccessGrant,
	type IssuancePolicy,
	type IssueLimits,
	issuancePolicies,
	subjectChecks,
	type Tokens,
	tokens,
} from "../src/contract.ts";
import { denylistAllowanceMs } from "../src/denylist/denylist.ts";
import tokensModule from "../src/module.ts";
import {
	type TokensUnderTest,
	tokensConfig,
	tokensContract,
	tokensStandIn,
} from "../src/testing.ts";
import { revokedInMemory } from "./revoked.ts";

/**
 * What both runs share: a clock the contract moves, a binding kind the composition knows, and a
 * subject check answering revoked for the subjects the contract revoked.
 */
function around() {
	let now = 1_800_000_000_000;
	const revoked = new Set<string>();
	const known = { member: "one", tokenType: "ONE" };
	const runtime = quietRuntime({ clock: { now: () => now } });
	const module = defineModule({ name: "around" }, (m) => [
		m.contribute(senderBindings).by(() => ({ ...known, read: async () => ({ kind: "absent" }) })),
		m.contribute(subjectChecks).by(() => ({
			holds: async (token) => (revoked.has(token.subject) ? "revoked" : "holds"),
		})),
	]);
	const place = (app: Assembly): TokensUnderTest => ({
		tokens: app.get(tokens),
		now: () => now,
		advance: (ms) => {
			now += ms;
		},
		known,
		revokeSubject: (subject) => {
			revoked.add(subject);
		},
	});
	return { runtime, module, place };
}

/** Issues through `issue`, which nothing here refuses, and answers what it issued. */
async function issueFor(t: Tokens, grant: AccessGrant, limits?: IssueLimits) {
	const issued = await t.issue({ grant, grantType: "test" }, limits);
	if (issued.kind !== "issued") throw new Error(`refused by ${issued.policy}`);
	return issued.access;
}

/** The policies given, contributed. */
const contributing = (policies: readonly IssuancePolicy[] = []) =>
	defineModule({ name: "policies" }, (m) =>
		policies.map((policy) => m.contribute(issuancePolicies).by(() => policy)),
	);

tokensContract("tokens over keys and a simulated store", async ({ revocable, policies }) => {
	const { runtime, module, place } = around();
	const app = await assemble({
		modules: [
			http,
			keysModule,
			issuerModule,
			senderBindingModule,
			tokensModule,
			revokedInMemory(() => runtime.clock.now()).module,
			module,
			contributing(policies),
		],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...keysConfig(),
			...issuerConfig(),
			...tokensConfig(
				{ revocation: revocable ? "denylist" : "unsupported" },
				{ subjects: "checked" },
			),
		},
		runtime,
	});
	return place(app);
});

tokensContract("the stand-in", async ({ revocable, policies }) => {
	const { runtime, module, place } = around();
	const app = await assemble({
		modules: [tokensStandIn({ revocable }), module, contributing(policies)],
		config: kernelConfig(),
		runtime,
	});
	return place(app);
});

it("the stand-in tells who a token was issued to for the allowance past its expiry, as tokens does", async () => {
	const { runtime, module, place } = around();
	const app = await assemble({
		modules: [tokensStandIn(), module],
		config: kernelConfig(),
		runtime,
	});
	const stand = place(app);
	const issued = await issueFor(stand.tokens, {
		subject: "s",
		issuedTo: "c",
		audience: ["api"],
		scope: [],
	});
	expect(await stand.tokens.verifyAccess("never issued")).toEqual({
		kind: "invalid",
		reason: "shape",
	});
	stand.advance(issued.expiresAt - stand.now() + denylistAllowanceMs - 1);
	expect(await stand.tokens.issuedToOf(issued.token)).toEqual({ kind: "issued", issuedTo: "c" });
	stand.advance(1);
	expect(await stand.tokens.issuedToOf(issued.token)).toEqual({ kind: "invalid" });
});
