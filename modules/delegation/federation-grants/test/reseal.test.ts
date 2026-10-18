import { randomBytes } from "node:crypto";
import { assemble, kernelConfig } from "@mod/kernel";
import { resealing, seal } from "@mod/seal";
import sealModule from "@mod/seal/module";
import { expect, it } from "vitest";
import { recordsWith } from "../src/grant/grant.ts";
import { harness } from "./harness.ts";

const key = (id: string) => ({ id, key: randomBytes(32).toString("base64") });
const [past, current, gone] = [key("past"), key("current"), key("gone")];
/** Grants' records over a seal of a ring of its own, to write what another key sealed. */
const recordsOver = async (ring: Readonly<Record<string, unknown>>) =>
	recordsWith(
		(await assemble({ modules: [sealModule], config: { ...kernelConfig(), seal: ring } })).get(
			seal,
		),
	);

/** A harness whose ring holds `past` as a previous key, and a way to put grants under `by`. */
async function rotated() {
	const h = await harness({ seal: { current, previous: [past] } });
	const now = await recordsOver({ current });
	/** A connected grant, its credentials then sealed by `by`; answers its id and what it holds sealed now. */
	const aged = async (by: { id: string; key: string }) => {
		const { id } = await h.connected();
		const grant = now.grantOf(await h.stores.grants.read(id));
		const credentials = grant && now.open(grant);
		if (!grant || !credentials) throw new Error("no grant");
		const sealed = (await recordsOver({ current: by })).seal(grant, credentials);
		await h.stores.grants.change(id, () => ({ value: now.stored({ ...grant, sealed }) }));
		return { id, sealedNow: async () => now.grantOf(await h.stores.grants.read(id))?.sealed };
	};
	const reseal = () => h.app.get(resealing).reseal();
	const counted = (resealed: number, left: number) => [
		{ name: "federation-grants", resealed, left },
	];
	return { ...h, aged, reseal, counted };
}

it("seals again each grant's credentials a past key sealed, walking every grant, and counts one no key opens as left", async () => {
	const h = await rotated();
	const [first, second, lost] = [await h.aged(past), await h.aged(past), await h.aged(gone)];
	expect(await h.reseal()).toEqual(h.counted(2, 1));
	expect(await first.sealedNow()).toMatch(/^current\./);
	expect(await second.sealedNow()).toMatch(/^current\./);
	expect(await lost.sealedNow()).toMatch(/^gone\./);
	expect(await h.reseal()).toEqual(h.counted(0, 1));
});

it("leaves credentials another write changed meanwhile, and does not count them", async () => {
	const h = await rotated();
	const aged = await h.aged(past);
	const now = await recordsOver({ current });
	h.stores.raceNext((record) => {
		const grant = now.grantOf(record);
		return grant ? now.stored({ ...grant, sealed: "current.theirs" }) : record;
	});
	expect(await h.reseal()).toEqual(h.counted(0, 0));
	expect(await aged.sealedNow()).toBe("current.theirs");
});
