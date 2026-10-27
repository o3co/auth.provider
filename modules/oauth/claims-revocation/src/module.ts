import { claimsSelections } from "@mod/claims-selection";
import { defineModule } from "@mod/kernel";
import { familyRevocation } from "@mod/refresh";
import { constrainedFamilyRevocation, type RevocationRun } from "./contract.ts";

export default defineModule(
	{ name: "claims-revocation", takes: [claimsSelections, familyRevocation] },
	(m) => [
		m.provide(constrainedFamilyRevocation).by(async (c) => {
			const selections = await c.get(claimsSelections);
			const families = await c.get(familyRevocation);
			return {
				run: async (): Promise<RevocationRun> => {
					// Outside draining, new constrained families may still start: a run would not be the last.
					if (selections.mode !== "draining")
						return { kind: "not-draining", mode: selections.mode };
					const done = await selections.constrainedFamilies((id) => families.revoke(id));
					const { shards, reads, handles, removals } = done.failed;
					return {
						kind: "run",
						revoked: done.handled,
						expired: done.expired,
						failed: { shards, reads, revocations: handles, removals },
					};
				},
			};
		}),
	],
);
