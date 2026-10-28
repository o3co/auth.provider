import { randomBytes } from "node:crypto";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { type Assembly, assemble, defineModule, kernelConfig, type Random } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import { senderBindings } from "@mod/sender-binding";
import senderBindingModule from "@mod/sender-binding/module";
import { denylistAllowanceMs } from "@mod/token-denylist";
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
function around(random?: Random) {
	let now = 1_800_000_000_000;
	const revoked = new Set<string>();
	const known = { member: "one", tokenType: "ONE" };
	const runtime = quietRuntime({ clock: { now: () => now }, ...(random ? { random } : {}) });
	const module = defineModule({ name: "around", replicaSafe: false, takes: [] }, (m) => [
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
	defineModule({ name: "policies", replicaSafe: true, takes: [] }, (m) =>
		policies.map((policy) => m.contribute(issuancePolicies).by(() => policy)),
	);

tokensContract(
	"tokens over keys and a simulated store",
	async ({ revocable, policies, lifetimeSeconds }) => {
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
					{
						revocation: revocable ? "denylist" : "unsupported",
						...(lifetimeSeconds === undefined
							? {}
							: { "access-token-lifetime": `${lifetimeSeconds}s` }),
					},
					{ subjects: "checked" },
				),
			},
			runtime,
		});
		return place(app);
	},
);

tokensContract("the stand-in", async ({ revocable, policies, lifetimeSeconds }) => {
	const { runtime, module, place } = around();
	const app = await assemble({
		modules: [
			tokensStandIn({
				revocable,
				...(lifetimeSeconds === undefined ? {} : { lifetimeSeconds }),
			}),
			module,
			contributing(policies),
		],
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

it("the stand-in keeps nothing of a token it refuses for want of a second left", async () => {
	// The bytes each id is drawn from, so the name of a token refused can be asked for.
	const drawn: Uint8Array[] = [];
	const { runtime, module, place } = around({
		bytes: (length) => {
			const bytes = new Uint8Array(randomBytes(length));
			drawn.push(bytes);
			return bytes;
		},
	});
	const app = await assemble({
		modules: [tokensStandIn(), module],
		config: kernelConfig(),
		runtime,
	});
	const stand = place(app);
	const grant = { subject: "s", issuedTo: "c", audience: ["api"], scope: [] };
	const lastName = () => `stand-in.${Buffer.from(drawn.at(-1) ?? []).toString("base64url")}`;
	expect(
		await stand.tokens.issue({ grant, grantType: "test" }, { notAfter: stand.now() + 999 }),
	).toMatchObject({ kind: "refused", reason: "no_lifetime_left" });
	expect(await stand.tokens.issuedToOf(lastName())).toEqual({ kind: "invalid" });
	// One issued is kept by the name its id makes.
	const issued = await issueFor(stand.tokens, grant, { notAfter: stand.now() + 1000 });
	expect(issued.token).toBe(lastName());
	expect(await stand.tokens.issuedToOf(issued.token)).toEqual({ kind: "issued", issuedTo: "c" });
});

it("the stand-in takes all it names, revocable or not", async () => {
	for (const revocable of [true, false]) {
		const { runtime, module } = around();
		const input = {
			modules: [tokensStandIn({ revocable }), module],
			config: kernelConfig(),
			runtime,
		};
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(input))["tokens"], String(revocable)).toBeUndefined();
	}
});
