import type { FactorStore } from "../store.ts";

/**
 * Why the factor store's ports cannot be used, or none, the one statement of them: `updateAsOne`
 * offered, to write a list and a claim as one; `erase` and `migrate` both or neither.
 */
export function portsRefused(store: FactorStore): string | undefined {
	if (typeof store.updateAsOne !== "function") {
		return "its factor store offers no updateAsOne, to write a list and a claim as one";
	}
	if ((store.erase === undefined) !== (store.migrate === undefined)) {
		return "its factor store offers part of erase and migrate: both, or neither";
	}
	return undefined;
}
