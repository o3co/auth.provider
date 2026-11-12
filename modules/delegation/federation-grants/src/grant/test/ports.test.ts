import { site } from "@mod/http";
import type { BuildContext } from "@mod/kernel";
import { upstreams } from "@mod/upstreams";
import { expect, it } from "vitest";
import type { Settings } from "../../section.ts";
import { grantStore, pendingIntents, subjectGrants } from "../../store.ts";
import { type ErasedStores, portsOf, portsRefused } from "../ports.ts";
import { sharedOver } from "../shared.ts";

const names = ["grants", "pending", "subjects"] as const;
const all = names.flatMap((name) => [`${name}.erase`, `${name}.migrate`]);
/** The three stores, each offering the ports listed and nothing else read. */
const storesWith = (offered: readonly string[]) =>
	Object.fromEntries(
		names.map((n) => [
			n,
			Object.fromEntries(
				offered
					.filter((o) => o.startsWith(`${n}.`))
					.map((o) => [o.slice(n.length + 1), async () => ({})]),
			),
		]),
	) as unknown as ErasedStores;
const refusal =
	"the grant, pending and subject stores offer part of their erase and migrate: all six, or none";

it("takes the stores' six erasure ports as one set, and refuses the boot at sharedOver on any part", async () => {
	expect([portsRefused(storesWith([])), portsRefused(storesWith(all))]).toEqual([
		undefined,
		undefined,
	]);
	expect(portsOf(storesWith(all))).toBeDefined();
	for (const missing of all) {
		const part = storesWith(all.filter((one) => one !== missing));
		expect([portsRefused(part), portsOf(part)], missing).toEqual([refusal, undefined]);
		const given = new Map<unknown, unknown>([
			[site, { origin: "https://as.example" }],
			[upstreams, { of: () => undefined }],
			[grantStore, part.grants],
			[pendingIntents, part.pending],
			[subjectGrants, part.subjects],
		]);
		const refuse = (_where: string, reason: string) => {
			throw new Error(reason);
		};
		const section = { connections: {}, "max-lifetime": 60, "keep-on-subject-revocation": false };
		const c = {
			get: async (key: unknown) => given.get(key),
			refuse,
			section,
			log: { warn: () => {} },
		};
		await expect(sharedOver(c as unknown as BuildContext<Settings>)).rejects.toThrow(refusal);
	}
});
