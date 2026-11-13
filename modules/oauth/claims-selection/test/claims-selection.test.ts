import type { Client } from "@mod/clients";
import { type Redeemed, type RedemptionHook, redemptionHooks } from "@mod/code-grant";
import { type TokenTie, tokenTies } from "@mod/grants";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { afterEach, expect, it } from "vitest";
import {
	claimScopes,
	claimsSelections,
	type Selection,
	type SelectionConsent,
	selectionConsents,
	selectionLimits,
	type Target,
	withinLimits,
} from "../src/contract.ts";
import claimsSelectionModule from "../src/module.ts";
import { read, stored } from "../src/stored.ts";
import { claimsSelectionInMemory } from "../src/testing.ts";
import { readAt0191 } from "./frozen-0.19.1.ts";

let shift = 0;
const runtime = quietRuntime({ clock: { now: () => 1_000_000 + shift } });
let stop = async () => {};
afterEach(async () => {
	shift = 0;
	await stop();
});

const seen = contract<{ hook: RedemptionHook; tie: TokenTie }>("seen");
/** Hands the contributed hook and tie to the test. */
const reader = defineModule(
	{ name: "reader", replicaSafe: false, takes: [redemptionHooks, tokenTies] },
	(m) => [
		m.provide(seen).by(async (c) => {
			const [hook] = await c.collect(redemptionHooks);
			const [tie] = await c.collect(tokenTies);
			if (!hook || !tie) throw new Error("nothing contributed");
			return { hook, tie };
		}),
	],
);
/** A consent judge that agrees to the scopes in `agreed`, which a test may change. */
const judging = (agreed: Set<string>, name = "judge") =>
	defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
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
	stores: { readonly module: Module } = claimsSelectionInMemory(),
) {
	const app = await assemble({
		modules: [claimsSelectionModule, stores.module, reader, ...extra],
		config: kernelConfig(),
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
		subject: "alice",
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
		// Neither: a constraint that names no value would hold back the claim it names whatever it holds.
		{},
		{ essential: true },
		{ value: ["a"] },
		{ value: { a: 1 } },
		{ value: null },
		{ value: Number.POSITIVE_INFINITY },
	]) {
		await expect(
			s.selections.select(client, "alice", constrained(past)),
			JSON.stringify(past),
		).rejects.toThrow(TypeError);
		await expect(s.selections.keepForCode("r", constrained(past), 1000, "alice")).rejects.toThrow(
			TypeError,
		);
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
	await s.selections.keepForCode("r-1", asked, 10_000, "alice");
	await s.hook.pin("r-1", "alice");
	// The code's record ends at its lifetime and a minute; the pin still answers.
	shift = 10_000 + 60_000;
	expect(await s.selections.forCode("r-1")).toEqual(asked);
	// A code with no selection is pinned as none.
	await s.hook.pin("r-2", "alice");
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
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await s.selections.keepForCode("r-2", asked, 600_000, "alice");
	shift = 600_000 + 59_999;
	await s.hook.pin("r-1", "alice");
	expect(await s.selections.forCode("r-1")).toEqual(asked);
	shift = 600_000 + 60_000;
	await s.hook.pin("r-2", "alice");
	expect(await s.selections.forCode("r-2")).toBeUndefined();
});

it("keeps nothing for a code whose selection holds no name and no constraint, and never a second for one name", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", { idToken: none, userinfo: none }, 600_000, "alice");
	expect(s.stores.names()).toEqual([]);
	await s.selections.keepForCode("r-2", asked, 600_000, "alice");
	await expect(s.selections.keepForCode("r-2", asked, 600_000, "alice")).rejects.toThrow();
});

it("keeps for a redeemed code's token the pinned userinfo target, until the token's end and two minutes more", async () => {
	const s = await serve();
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await s.hook.pin("r-1", "alice");
	await s.hook.redeemed(redeemedOf("r-1", "tok-1", 3_600_000));
	expect(await s.selections.forToken("tok-1")).toEqual(asked.userinfo);
	shift = 3_600_000 + 119_999;
	expect(await s.selections.forToken("tok-1")).toEqual(asked.userinfo);
	shift = 3_600_000 + 120_000;
	expect(await s.selections.forToken("tok-1")).toBeUndefined();
	// None for a token whose code had no selection; a redemption whose pin is gone fails.
	await s.hook.pin("r-2", "alice");
	await s.hook.redeemed(redeemedOf("r-2", "tok-2"));
	expect(await s.selections.forToken("tok-2")).toBeUndefined();
	await expect(s.hook.redeemed(redeemedOf("r-3", "tok-3"))).rejects.toThrow();
});

it("keeps a family's target, and cuts a refreshed token's names to what is allowed and agreed to now, never the family's record", async () => {
	const agreed = new Set(["profile"]);
	const s = await serve([judging(agreed)]);
	const scopes = ["openid", "profile"];
	const client = clientAllowed(scopes);
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await s.hook.pin("r-1", "alice");
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
	await s.hook.pin("r-2", "alice");
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
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await s.hook.pin("r-1", "alice");
	await s.hook.redeemed(redeemedOf("r-1", "tok-1"));
	const tie = await s.tie.tieOf("tok-1");
	if (tie.kind !== "held") throw new Error("not held");
	expect(tie.ends).toBeUndefined();
	expect(tie.session).toBeUndefined();
	expect(await tie.join({ id: "tok-x", expiresAt: runtime.clock.now() + 600_000 }, "alice")).toBe(
		true,
	);
	expect(await s.selections.forToken("tok-x")).toEqual({
		names: [],
		constraints: asked.userinfo.constraints,
	});
	// A token with names only, or with nothing, ties nothing.
	const named: Selection = { idToken: none, userinfo: { names: [name], constraints: [] } };
	await s.selections.keepForCode("r-2", named, 600_000, "alice");
	await s.hook.pin("r-2", "alice");
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

it("reads a record of either format alike: 2 keeping its subject, 1 as 0.19 wrote it, without one", async () => {
	const s = await serve();
	for (const [n, format] of [
		[1, { format: 1 }],
		[2, { format: 2, subject: "alice" }],
	] as const) {
		s.stores.overwrite(`c.r-${n}`, { ...format, selection: asked });
		s.stores.overwrite(`t.tok-${n}`, { ...format, target: asked.userinfo });
		s.stores.overwrite(`p.r-${n + 2}`, { ...format, selection: asked });
		await s.hook.pin(`r-${n}`, "alice");
		expect(await s.selections.forCode(`r-${n}`)).toEqual(asked);
		expect(await s.selections.forCode(`r-${n + 2}`)).toEqual(asked);
		expect(await s.selections.forToken(`tok-${n}`)).toEqual(asked.userinfo);
	}
	// Format 2 without its subject is a record it cannot read.
	s.stores.overwrite("t.tok-5", { format: 2, target: asked.userinfo });
	await expect(s.selections.forToken("tok-5")).rejects.toSatisfy(isUnavailable);
});

it("writes format 2, keeping the subject, where one is given; format 1 without, until every write gives one", () => {
	expect(stored.code(asked, "alice")).toEqual({ format: 2, subject: "alice", selection: asked });
	expect(stored.pin(undefined, "alice")).toEqual({ format: 2, subject: "alice" });
	expect(stored.target(none, "alice")).toEqual({ format: 2, subject: "alice", target: none });
	expect([stored.code(asked), stored.pin(undefined), stored.target(none)]).toEqual([
		{ format: 1, selection: asked },
		{ format: 1 },
		{ format: 1, target: none },
	]);
	expect(read.code(stored.code(asked, "alice"))).toEqual({ selection: asked, subject: "alice" });
});

/** Records in memory offered through `create`, answering `erased` for a subject in `erased`. */
const fencing = (erased: Set<string>) =>
	claimsSelectionInMemory({
		around: (records) => ({
			read: records.read,
			create: async (name, kept, ms, subject) =>
				erased.has(subject) ? "erased" : records.create(name, kept, ms, subject),
		}),
	});
/** Records in memory offered through `save`, as a store not filing by subject. */
const unfiled = () =>
	claimsSelectionInMemory({
		around: (records) => ({
			read: records.read,
			save: async (name, kept, ms) =>
				(await records.create(name, kept, ms, "unfiled")) === "created" ? "created" : "exists",
		}),
	});
const issuedAt = (id: string) => ({ id, expiresAt: runtime.clock.now() + 600_000 });

it("writes format 2 wherever the subject is known, through save too", async () => {
	const s = await serve(undefined, unfiled());
	await s.selections.keepForCode("r-1", asked, 600_000);
	await s.hook.pin("r-1", "alice");
	expect(await s.stores.records.read("c.r-1")).toEqual({ format: 1, selection: asked });
	expect(await s.stores.records.read("p.r-1")).toEqual({
		format: 2,
		subject: "alice",
		selection: asked,
	});
	await s.selections.keepForCode("r-2", asked, 600_000, "alice");
	expect(await s.stores.records.read("c.r-2")).toMatchObject({ format: 2, subject: "alice" });
});

it("refuses to keep a code's selection for an erased subject, as unavailable, apart from a name kept already", async () => {
	const s = await serve(undefined, fencing(new Set(["erin"])));
	await expect(s.selections.keepForCode("r-1", asked, 600_000, "erin")).rejects.toSatisfy(
		isUnavailable,
	);
	expect(s.stores.names()).toEqual([]);
	await s.selections.keepForCode("r-2", asked, 600_000, "alice");
	await expect(s.selections.keepForCode("r-2", asked, 600_000, "alice")).rejects.toSatisfy(
		isUnavailable,
	);
});

it("fails every write past its subject's erasure as unavailable, except a join, which answers false", async () => {
	const erased = new Set<string>();
	const s = await serve(undefined, fencing(erased));
	const client = clientAllowed(["openid", "profile"]);
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await s.hook.pin("r-1", "alice");
	await s.selections.follow("r-1", "fam-1", 86_400_000);
	await s.hook.redeemed(redeemedOf("r-1", "tok-1"));
	const tie = await s.tie.tieOf("tok-1");
	if (tie.kind !== "held") throw new Error("not held");
	await s.selections.keepForCode("r-2", asked, 600_000, "alice");
	erased.add("alice");
	await expect(s.hook.pin("r-2", "alice")).rejects.toSatisfy(isUnavailable);
	await expect(s.hook.redeemed(redeemedOf("r-1", "tok-2"))).rejects.toSatisfy(isUnavailable);
	await expect(s.selections.follow("r-1", "fam-2", 86_400_000)).rejects.toSatisfy(isUnavailable);
	await expect(
		s.selections.forRefreshed("fam-1", client, "alice", issuedAt("tok-3")),
	).rejects.toSatisfy(isUnavailable);
	expect(await tie.join(issuedAt("tok-4"), "alice")).toBe(false);
});

it("takes a format-2 record's own subject, refusing as unavailable a caller's that differs", async () => {
	const s = await serve();
	const client = clientAllowed(["openid", "profile"]);
	await s.selections.keepForCode("r-1", asked, 600_000, "alice");
	await expect(s.hook.pin("r-1", "bob")).rejects.toSatisfy(isUnavailable);
	await s.hook.pin("r-1", "alice");
	await expect(
		s.hook.redeemed({ ...redeemedOf("r-1", "tok-1"), subject: "bob" }),
	).rejects.toSatisfy(isUnavailable);
	await s.hook.redeemed(redeemedOf("r-1", "tok-1"));
	const tie = await s.tie.tieOf("tok-1");
	if (tie.kind !== "held") throw new Error("not held");
	await expect(tie.join(issuedAt("tok-2"), "bob")).rejects.toSatisfy(isUnavailable);
	expect(await tie.join(issuedAt("tok-3"), "alice")).toBe(true);
	expect(await s.stores.records.read("t.tok-3")).toMatchObject({ format: 2, subject: "alice" });
	await s.selections.follow("r-1", "fam-1", 86_400_000);
	await expect(
		s.selections.forRefreshed("fam-1", client, "bob", issuedAt("tok-4")),
	).rejects.toSatisfy(isUnavailable);
});

it("refuses as unavailable a family or a token written from a pin without its subject, a defect", async () => {
	const s = await serve();
	s.stores.overwrite("p.r-1", { format: 1, selection: asked });
	await expect(s.selections.follow("r-1", "fam-1", 86_400_000)).rejects.toSatisfy(isUnavailable);
	await expect(s.hook.redeemed(redeemedOf("r-1", "tok-1"))).rejects.toSatisfy(isUnavailable);
	// An empty pin without one is the same defect.
	s.stores.overwrite("p.r-2", { format: 1 });
	await expect(s.selections.follow("r-2", "fam-2", 86_400_000)).rejects.toSatisfy(isUnavailable);
	expect(s.stores.names().filter((n) => !n.startsWith("p."))).toEqual([]);
});

it("throws a TypeError for a write without its subject to a store filing by subject: the caller's bug", async () => {
	const s = await serve(undefined, fencing(new Set()));
	await expect(s.selections.keepForCode("r-1", asked, 600_000)).rejects.toThrow(TypeError);
	// As a caller past the types would.
	const untyped = s.hook.pin as (redemption: string) => Promise<void>;
	await expect(untyped("r-1")).rejects.toThrow(TypeError);
});

it("refuses to start on a store offering both or neither of save and create, or part of erase and migrate", async () => {
	const { module: kept, records } = claimsSelectionInMemory();
	const offering = (offered: object) =>
		claimsSelectionInMemory({ around: () => ({ read: records.read, ...offered }) as never });
	const create = async () => "created" as const;
	const save = async () => "created" as const;
	const erase = async () => {
		throw new Error("not called");
	};
	expect(kept).toBeDefined();
	for (const [offered, reason] of [
		[{ save, create }, "exactly one"],
		[{}, "exactly one"],
		[{ create, erase }, "both, or neither"],
	] as const) {
		const refused = await serve(undefined, offering(offered)).catch((e: unknown) => e);
		expect(refused, reason).toMatchObject({
			refusals: [expect.objectContaining({ reason: expect.stringContaining(reason) })],
		});
	}
});

it("fails closed on 0.19.1, which reads a format-2 record as unavailable, never as none", () => {
	const written = [
		[readAt0191.code, stored.code(asked, "alice")],
		[readAt0191.pin, stored.pin(asked, "alice")],
		[readAt0191.pin, stored.pin(undefined, "alice")],
		[readAt0191.target, stored.target(asked.userinfo, "alice")],
	] as const;
	for (const [reading, record] of written) {
		expect(() => reading(record)).toThrow(Unavailable);
	}
	// Format 1, as 0.20 still writes it without a subject, reads there as before.
	expect(readAt0191.code(stored.code(asked))).toEqual({ format: 1, selection: asked });
});

it("has no section: a configuration that writes one is refused at boot", async () => {
	const written = assemble({
		modules: [claimsSelectionModule, claimsSelectionInMemory().module],
		config: { ...kernelConfig(), "claims-selection": { mode: "on" } },
		runtime,
	});
	const refused = await written.catch((error: unknown) => error);
	// The refusal names the section, so an operator sees which key to take out.
	expect(BootRefused.is(refused) && refused.refusals).toEqual([
		{ where: "claims-selection", reason: "module without a section" },
	]);
});

/** A table of claim scopes, as the module releasing claims contributes it. */
const scoping = (table: Record<string, string>, name = "scoping") =>
	defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
		m.contribute(claimScopes).by(() => ({ scopeOf: (claim: string) => table[claim] })),
	]);

it("names a claim's scope as the contributed table does, none without one, and refuses to start with two", async () => {
	const s = await serve([scoping({ name: "profile" })]);
	expect(s.selections.scopeOf("name")).toBe("profile");
	expect(s.selections.scopeOf("email")).toBeUndefined();
	await stop();
	expect((await serve([])).selections.scopeOf("name")).toBeUndefined();
	await stop();
	const twice = serve([scoping({}), scoping({}, "second-scoping")]);
	await expect(twice).rejects.toMatchObject({
		refusals: [expect.objectContaining({ reason: "more than one table of claim scopes" })],
	});
});

it("offers the bounds check a selection is held to", () => {
	const fits: Selection = {
		idToken: none,
		userinfo: { names: [name], constraints: [{ name: "name", value: "A" }] },
	};
	expect(withinLimits(fits)).toBe(true);
	expect(
		withinLimits({ ...fits, userinfo: { names: [], constraints: [{ name: "name", values: [] }] } }),
	).toBe(false);
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
