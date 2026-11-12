import type { FactorStore } from "../store.ts";

/**
 * Why the factor store's ports cannot be used, or none, the one statement of them: exactly one of
 * `updateTogether` and `updateAsOne`, and `erase` and `migrate` both or neither.
 */
export function portsRefused(store: FactorStore): string | undefined {
	const joint = [store.updateTogether, store.updateAsOne].filter((port) => port !== undefined);
	if (joint.length !== 1) {
		return "its factor store offers updateTogether or updateAsOne: exactly one, to write a list and a claim as one";
	}
	if ((store.erase === undefined) !== (store.migrate === undefined)) {
		return "its factor store offers part of erase and migrate: both, or neither";
	}
	return undefined;
}
