import { claimsSelections, type SelectionMode, type Target } from "@mod/claims-selection";
import claimsSelectionModule from "@mod/claims-selection/module";
import { claimsSelectionConfig, claimsSelectionInMemory } from "@mod/claims-selection/testing";
import { type RedemptionHook, redemptionHooks } from "@mod/code-grant";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { familyRevocation } from "@mod/refresh";
import { afterEach, describe, expect, it } from "vitest";
import { constrainedFamilyRevocation } from "../src/contract.ts";
import revocationModule from "../src/module.ts";

let shift = 0;
const runtime = quietRuntime({ clock: { now: () => 1_000_000 + shift } });
const stops: (() => Promise<void>)[] = [];
afterEach(async () => {
	shift = 0;
	for (const stop of stops.splice(0)) await stop();
});

const pins = contract<RedemptionHook>("pins");
/** Hands the contributed redemption hook to the test, to pin a code as a redemption does. */
const reader = defineModule({ name: "reader", takes: [redemptionHooks] }, (m) => [
	m.provide(pins).by(async (c) => {
		const [hook] = await c.collect(redemptionHooks);
		if (!hook) throw new Error("nothing contributed");
		return hook;
	}),
]);

/** refresh's revocation, standing in: each id asked, and a failure for each id in `failing`. */
function revocations() {
	const revoked: string[] = [];
	const failing = new Set<string>();
	const module = defineModule({ name: "revocations", takes: [] }, (m) => [
		m.provide(familyRevocation).by(() => ({
			revoke: async (id: string) => {
				if (failing.has(id)) throw new Unavailable("refresh");
				revoked.push(id);
			},
		})),
	]);
	return { module, revoked, failing };
}

const constrained: Target = { names: [], constraints: [{ name: "email", value: "a@example.com" }] };
const named: Target = { names: [{ name: "name", scope: "profile" }], constraints: [] };
const none: Target = { names: [], constraints: [] };

async function serve(
	mode: SelectionMode,
	stores: ReturnType<typeof claimsSelectionInMemory>,
	refresh = revocations(),
) {
	const app = await assemble({
		modules: [claimsSelectionModule, stores.module, reader, refresh.module, revocationModule],
		config: { ...kernelConfig(), ...claimsSelectionConfig({ mode }) },
		runtime,
	});
	await app.start();
	stops.push(() => app.stop(1000));
	return { app, refresh, run: () => app.get(constrainedFamilyRevocation).run() };
}

/** Founds each family from a code kept with `userinfo`, on a host that is on. */
async function founded(
	stores: ReturnType<typeof claimsSelectionInMemory>,
	families: readonly [string, Target, number?][],
) {
	const on = await serve("on", stores);
	const selections = on.app.get(claimsSelections);
	for (const [id, userinfo, lifetimeMs = 86_400_000] of families) {
		await selections.keepForCode(`r-${id}`, { idToken: none, userinfo }, 600_000);
		await on.app.get(pins).pin(`r-${id}`);
		await selections.follow(`r-${id}`, id, lifetimeMs);
	}
}

describe("revoking the families whose selection holds constraints", () => {
	it("revokes each constrained family while draining, and no other, and none again", async () => {
		const stores = claimsSelectionInMemory();
		await founded(stores, [
			["fam-a", constrained],
			["fam-b", constrained],
			["fam-named", named],
		]);
		const draining = await serve("draining", stores);
		expect(await draining.run()).toEqual({
			kind: "run",
			revoked: 2,
			expired: 0,
			failed: { shards: 0, reads: 0, revocations: 0, removals: 0 },
		});
		expect(draining.refresh.revoked.sort()).toEqual(["fam-a", "fam-b"]);
		expect(await draining.run()).toMatchObject({ kind: "run", revoked: 0 });
		expect(draining.refresh.revoked).toHaveLength(2);
	});

	it("revokes nothing and touches nothing while on or off", async () => {
		const stores = claimsSelectionInMemory();
		await founded(stores, [["fam-a", constrained]]);
		for (const mode of ["on", "off"] as const) {
			const host = await serve(mode, stores);
			expect(await host.run()).toEqual({ kind: "not-draining", mode });
			expect(host.refresh.revoked).toEqual([]);
		}
		expect(stores.listed()).toEqual(["fam-a"]);
	});

	it("counts a revocation that fails and keeps its family listed, so a run again revokes it", async () => {
		const stores = claimsSelectionInMemory();
		await founded(stores, [
			["fam-a", constrained],
			["fam-b", constrained],
		]);
		const refresh = revocations();
		refresh.failing.add("fam-b");
		const draining = await serve("draining", stores, refresh);
		expect(await draining.run()).toMatchObject({
			revoked: 1,
			failed: { shards: 0, reads: 0, revocations: 1, removals: 0 },
		});
		expect(stores.listed()).toEqual(["fam-b"]);
		refresh.failing.clear();
		expect(await draining.run()).toMatchObject({ revoked: 1, failed: { revocations: 0 } });
		expect(refresh.revoked.sort()).toEqual(["fam-a", "fam-b"]);
		expect(stores.listed()).toEqual([]);
	});

	it("unlists without revoking a family whose selection ran out, as the family did", async () => {
		const stores = claimsSelectionInMemory();
		await founded(stores, [
			["fam-short", constrained, 1000],
			["fam-long", constrained],
		]);
		shift = 1000;
		const draining = await serve("draining", stores);
		expect(await draining.run()).toMatchObject({ revoked: 1, expired: 1 });
		expect(draining.refresh.revoked).toEqual(["fam-long"]);
	});
});
