import type { IssuanceFence, IssuanceFencing } from "../contract.ts";

/** The receipt id's bytes: unguessable, one per bundle. */
const idBytes = 16;

/** Passing bundles through `fences`, each bundle under one receipt id from `random`. */
export function fencingOver(
	fences: readonly IssuanceFence[],
	random: { bytes(n: number): Uint8Array },
): IssuanceFencing {
	return {
		pass: async ({ subject }) => {
			if (fences.length === 0) return { kind: "passed" };
			const receiptId = Buffer.from(random.bytes(idBytes)).toString("base64url");
			for (const fence of fences) {
				if ((await fence.fence({ subject, receiptId })) === "refused") {
					return { kind: "refused", fence: fence.name };
				}
			}
			return { kind: "passed" };
		},
	};
}
