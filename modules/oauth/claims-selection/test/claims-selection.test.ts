import type { Client } from "@mod/clients";
import { type Redeemed, type RedemptionHook, redemptionHooks } from "@mod/code-grant";
import { type TokenTie, tokenTies } from "@mod/grants";
import {
	assemble,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { afterEach, expect, it } from "vitest";
import {
	claimsSelections,
	type Selection,
	type SelectionConsent,
	selectionConsents,
	selectionLimits,
	selectionRecords,
	type Target,
} from "../src/contract.ts";
import claimsSelectionModule from "../src/module.ts";
import { claimsSelectionConfig, claimsSelectionInMemory } from "../src/testing.ts";

let shift = 0;
const runtime = quietRuntime({ clock: { now: () => 1_000_000 + shift } });
let stop = async () => {};
afterEach(async () => {
	shift = 0;
	await stop();
});

const seen = contract<{ hook: RedemptionHook; tie: TokenTie }>("seen");
/** Hands the contributed hook and tie to the test. */
const reader = defineModule({ name: "reader", takes: [redemptionHooks, tokenTies] }, (m) => [
	m.provide(seen).by(async (c) => {
		const [hook] = await c.collect(redemptionHooks);
		const [tie] = await c.collect(tokenTies);
		if (!hook || !tie) throw new Error("nothing contributed");
		return { hook, tie };
	}),
]);
/** A consent judge that agrees to the scopes in `agreed`, which a test may change. */
const judging = (agreed: Set<string>, name = "judge") =>
	defineModule({ name, takes: [] }, (m) => [
		m
			.contribute(selectionConsents)
			.by((): SelectionConsent => ({ consented: async (_c, _s, scope) => agreed.has(scope) })),
	]);
/** A client allowed the scopes in `scopes`, which a test may change. */
const clientAllowed = (scopes: string[]): Client => ({
	id: "app",
	kind: "confidential",
	method: "client_secret_basic",
	registered: true,
	section: <T>() => ({ grants: [], scopes, audiences: [] }) as T,
});

async function serve(
	extra: Module[] = [judging(new Set(["profile", "email"]))],
	mode: "off" | "draining" | "on" = "on",
	stores: { readonly module: Module } = claimsSelectionInMemory(),
) {
	const app = await assemble({
		modules: [claimsSelectionModule, stores.module, reader, ...extra],
		config: { ...kernelConfig(), ...claimsSelectionConfig({ mode }) },
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	return {
		app,
		stores: stores as ReturnType<typeof claimsSelectionInMemory>,
		selections: app.get(claimsSelections),
		...app.get(seen),
	};
}

const none: Target = { names: [], constraints: [] };
const name = { name: "name", scope: "profile" };
const email = { name: "email", scope: "email" };
const groups = { name: "groups", scope: "groups" };
const asked: Selection = {
	idToken: { names: [email], constraints: [] },
	userinfo: {
		names: [name, groups],
		constraints: [{ name: "email", value: "a@example.com" }],
	},
};
const redeemedOf = (redemption: string, id: string, expiresIn = 600_000) =>
	({
		redemption,
		access: { id, expiresAt: runtime.clock.now() + expiresIn, expiresIn: 600, tokenType: "Bearer" },
	}) as unknown as Redeemed;

it("selects the names whose scope the client is allowed and the subject agreed to, keeping every constraint", async () => {
	const s = await serve([judging(new Set(["profile", "groups"]))]);
	const client = clientAllowed(["openid", "profile", "email"]);
	expect(await s.selections.select(client, "alice", asked)).toEqual({
		// email is allowed but not agreed to; groups is agreed to but not allowed.
		idToken: none,
		userinfo: { names: [name], constraints: asked.userinfo.constraints },
	});
});

it("selects no name where no module judges consent, and refuses to start with two", async () => {
	const s = await serve([]);
	const client = clientAllowed(["openid", "profile", "email", "groups"]);
	expect(await s.selections.select(client, "alice", asked)).toEqual({
		idToken: none,
		userinfo: { names: [], constraints: asked.userinfo.constraints },
	});
	await stop();
	const twice = serve([judging(new Set()), judging(new Set(), "second-judge")]);
	await expect(twice).rejects.toMatchObject({
		refusals: [expect.objectContaining({ reason: "more than one judge of consent" })],
	});
});

it("refuses a selection past its bounds, or with a value no scalar", async () => {
	const s = await serve();
	const client = clientAllowed(["profile"]);
	const constrained = (constraint: object): Selection => ({
		idToken: none,
		userinfo: {
			names: [],
			constraints: [{ name: "name", ...constraint }] as Target["constraints"],
		},
	});
	const long = "x".repeat(selectionLimits.valueLength);
	expect(await s.selections.select(client, "alice", constrained({ value: long }))).toBeDefined();
	for (const past of [
		{ value: `${long}x` },
		{ values: Array.from({ length: selectionLimits.values + 1 }, (_, i) => `v${i}`) },
		{ values: [] },
		{ value: "a", values: ["b"] },
		{ value: ["a"] },
		{ value: { a: 1 } },
		{ value: null },
		{ value: Number.POSITIVE_INFINITY },
	]) {
		await expect(
			s.selections.select(client, "alice", constrained(past)),
			JSON.stringify(past),
		).rejects.toThrow(TypeError);
		await expect(s.selections.keepForCode("r", constrained(past), 1000)).rejects.toThrow(TypeError);
	}
	const many: Selection = {
		idToken: none,
		userinfo: {
			names: [],
			constraints: Array.from({ length: 40 }, (_, i) => ({ name: `n${i}`, values: [long] })),
		},
	};
	await expect(s.selections.select(client, "alice", many)).rejects.toThrow(TypeError);
});

it("pins a code's selection at its redemption, and answers that pin through the exchange, even past the code's own record", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", asked, 10_000);
	await s.hook.pin("r-1");
	// The code's record ends at its lifetime and a minute; the pin still answers.
	shift = 10_000 + 60_000;
	expect(await s.selections.forCode("r-1")).toEqual(asked);
	// A code with no selection is pinned as none.
	await s.hook.pin("r-2");
	expect(await s.selections.forCode("r-2")).toBeUndefined();
	// The pin holds five minutes, not as a deadline: after that, a read fails rather than answer none.
	shift += 300_000;
	await expect(s.selections.forCode("r-1")).rejects.toThrow();
	await expect(s.selections.forCode("r-2")).rejects.toThrow();
	// A redemption never pinned fails the same way.
	await expect(s.selections.forCode("r-3")).rejects.toThrow();
});

it("keeps a code's selection for its lifetime and a minute more, so a code still alive at its pin finds it", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", asked, 600_000);
	await s.selections.keepForCode("r-2", asked, 600_000);
	shift = 600_000 + 59_999;
	await s.hook.pin("r-1");
	expect(await s.selections.forCode("r-1")).toEqual(asked);
	shift = 600_000 + 60_000;
	await s.hook.pin("r-2");
	expect(await s.selections.forCode("r-2")).toBeUndefined();
});

it("keeps nothing for a code whose selection holds no name and no constraint, and never a second for one name", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", { idToken: none, userinfo: none }, 600_000);
	expect(s.stores.names()).toEqual([]);
	await s.selections.keepForCode("r-2", asked, 600_000);
	await expect(s.selections.keepForCode("r-2", asked, 600_000)).rejects.toThrow();
});

it("keeps for a redeemed code's token the pinned userinfo target, until the token's end and two minutes more", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", asked, 600_000);
	await s.hook.pin("r-1");
	await s.hook.redeemed(redeemedOf("r-1", "tok-1", 3_600_000));
	expect(await s.selections.forToken("tok-1")).toEqual(asked.userinfo);
	shift = 3_600_000 + 119_999;
	expect(await s.selections.forToken("tok-1")).toEqual(asked.userinfo);
	shift = 3_600_000 + 120_000;
	expect(await s.selections.forToken("tok-1")).toBeUndefined();
	// None for a token whose code had no selection; a redemption whose pin is gone fails.
	await s.hook.pin("r-2");
	await s.hook.redeemed(redeemedOf("r-2", "tok-2"));
	expect(await s.selections.forToken("tok-2")).toBeUndefined();
	await expect(s.hook.redeemed(redeemedOf("r-3", "tok-3"))).rejects.toThrow();
});

it("keeps a family's target, and cuts a refreshed token's names to what is allowed and agreed to now, never the family's record", async () => {
	const agreed = new Set(["profile"]);
	const s = await serve([judging(agreed)]);
	const scopes = ["openid", "profile"];
	const client = clientAllowed(scopes);
	await s.selections.keepForCode("r-1", asked, 600_000);
	await s.hook.pin("r-1");
	await s.selections.follow("r-1", "fam-1", 86_400_000);
	await s.selections.forRefreshed("fam-1", client, "alice", {
		id: "tok-1",
		expiresAt: runtime.clock.now() + 600_000,
	});
	// groups was never allowed; name is.
	expect(await s.selections.forToken("tok-1")).toEqual({
		names: [name],
		constraints: asked.userinfo.constraints,
	});
	// The allowance taken away: the name goes, the constraint stays.
	scopes.splice(scopes.indexOf("profile"), 1);
	await s.selections.forRefreshed("fam-1", client, "alice", {
		id: "tok-2",
		expiresAt: runtime.clock.now() + 600_000,
	});
	expect(await s.selections.forToken("tok-2")).toEqual({
		names: [],
		constraints: asked.userinfo.constraints,
	});
	// Consent withdrawn while allowed: the name goes too.
	scopes.push("profile");
	agreed.delete("profile");
	await s.selections.forRefreshed("fam-1", client, "alice", {
		id: "tok-3",
		expiresAt: runtime.clock.now() + 600_000,
	});
	expect(await s.selections.forToken("tok-3")).toEqual({
		names: [],
		constraints: asked.userinfo.constraints,
	});
	// Both back: the family's record was never cut, so the name comes back.
	agreed.add("profile");
	await s.selections.forRefreshed("fam-1", client, "alice", {
		id: "tok-4",
		expiresAt: runtime.clock.now() + 600_000,
	});
	expect(await s.selections.forToken("tok-4")).toEqual({
		names: [name],
		constraints: asked.userinfo.constraints,
	});
	// A family founded from a code without a selection keeps none; its refreshed tokens none.
	await s.hook.pin("r-2");
	await s.selections.follow("r-2", "fam-2", 86_400_000);
	await s.selections.forRefreshed("fam-2", client, "alice", {
		id: "tok-5",
		expiresAt: runtime.clock.now() + 600_000,
	});
	expect(await s.selections.forToken("tok-5")).toBeUndefined();
	// Founding after the pin is gone fails.
	await expect(s.selections.follow("r-3", "fam-3", 86_400_000)).rejects.toThrow();
});

it("ties an exchanged token to the constraints of its subject token, never to its names", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", asked, 600_000);
	await s.hook.pin("r-1");
	await s.hook.redeemed(redeemedOf("r-1", "tok-1"));
	const tie = await s.tie.tieOf("tok-1");
	if (tie.kind !== "held") throw new Error("not held");
	expect(tie.ends).toBeUndefined();
	expect(tie.session).toBeUndefined();
	expect(await tie.join({ id: "tok-x", expiresAt: runtime.clock.now() + 600_000 })).toBe(true);
	expect(await s.selections.forToken("tok-x")).toEqual({
		names: [],
		constraints: asked.userinfo.constraints,
	});
	// A token with names only, or with nothing, ties nothing.
	const named: Selection = { idToken: none, userinfo: { names: [name], constraints: [] } };
	await s.selections.keepForCode("r-2", named, 600_000);
	await s.hook.pin("r-2");
	await s.hook.redeemed(redeemedOf("r-2", "tok-2"));
	expect(await s.tie.tieOf("tok-2")).toEqual({ kind: "none" });
	expect(await s.tie.tieOf("tok-unknown")).toEqual({ kind: "none" });
});

it("fails a read of a record it cannot read as unavailable, never taking it for none", async () => {
	const s = await serve();
	s.stores.overwrite("t.tok-1", { format: 2, target: none });
	s.stores.overwrite("p.r-1", { format: 1, selection: { idToken: none } });
	const unreadable = { what: "claims-selection: a record it cannot read" };
	await expect(s.selections.forToken("tok-1")).rejects.toMatchObject(unreadable);
	await expect(s.selections.forCode("r-1")).rejects.toMatchObject(unreadable);
	await expect(s.tie.tieOf("tok-1")).rejects.toMatchObject(unreadable);
	await expect(s.selections.forToken("tok-1")).rejects.toSatisfy(isUnavailable);
});

/** A store that fails every call, to show a mode that never touches it. */
const untouchable = defineModule({ name: "untouchable-stores", takes: [] }, (m) => [
	m.provide(selectionRecords).by(() => ({
		save: async () => {
			throw new Error("touched");
		},
		read: async () => {
			throw new Error("touched");
		},
	})),
]);

it("touches no store when off: nothing pinned, kept or read, and refuses to keep a code's selection", async () => {
	const s = await serve(undefined, "off", { module: untouchable });
	expect(s.selections.mode).toBe("off");
	const client = clientAllowed(["profile"]);
	await s.hook.pin("r-1");
	expect(await s.selections.forCode("r-1")).toBeUndefined();
	await s.hook.redeemed(redeemedOf("r-1", "tok-1"));
	await s.selections.follow("r-1", "fam-1", 86_400_000);
	await s.selections.forRefreshed("fam-1", client, "alice", {
		id: "tok-2",
		expiresAt: runtime.clock.now() + 600_000,
	});
	expect(await s.selections.forToken("tok-1")).toBeUndefined();
	expect(await s.tie.tieOf("tok-1")).toEqual({ kind: "none" });
	await expect(s.selections.keepForCode("r-2", asked, 600_000)).rejects.toThrow(TypeError);
});

it("keeps reading, pinning and holding back what is kept when draining, but keeps no new selection", async () => {
	const stores = claimsSelectionInMemory();
	const on = await serve(undefined, "on", stores);
	await on.selections.keepForCode("r-1", asked, 600_000);
	await stop();
	const s = await serve(undefined, "draining", stores);
	expect(s.selections.mode).toBe("draining");
	await s.hook.pin("r-1");
	expect(await s.selections.forCode("r-1")).toEqual(asked);
	await s.hook.redeemed(redeemedOf("r-1", "tok-1"));
	expect(await s.selections.forToken("tok-1")).toEqual(asked.userinfo);
	await expect(s.hook.redeemed(redeemedOf("r-3", "tok-3"))).rejects.toThrow();
	await expect(s.selections.keepForCode("r-2", asked, 600_000)).rejects.toThrow(TypeError);
});

it("reads its mode as an operator writes it, on by default, and refuses another value", async () => {
	const stores = claimsSelectionInMemory();
	const app = await assemble({
		modules: [claimsSelectionModule, stores.module],
		config: kernelConfig(),
		runtime,
	});
	expect(app.get(claimsSelections).mode).toBe("on");
	await expect(serve(undefined, "sometimes" as never)).rejects.toThrow();
});

it("takes all its module names", async () => {
	const stores = claimsSelectionInMemory();
	const input = {
		modules: [claimsSelectionModule, stores.module, judging(new Set())],
		config: kernelConfig(),
		runtime,
	};
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(input))["claims-selection"]).toBeUndefined();
});
