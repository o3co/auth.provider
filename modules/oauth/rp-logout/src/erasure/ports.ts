import type { NoticeBodies } from "../store.ts";

/** Why the bodies' erasure ports cannot be used, or none: `erase` and `migrate`, both or neither. */
export function portsRefused(bodies: NoticeBodies): string | undefined {
	if ((bodies.erase === undefined) !== (bodies.migrate === undefined)) {
		return "the notice bodies offer part of their erase and migrate: both, or neither";
	}
	return undefined;
}

/** The bodies' erasure ports, where both are offered, each called on the bodies; none otherwise. */
export function portsOf(bodies: NoticeBodies) {
	const { erase, migrate } = bodies;
	if (!erase || !migrate) return undefined;
	return {
		erase: (...args: Parameters<typeof erase>) => erase.apply(bodies, args),
		migrate: (...args: Parameters<typeof migrate>) => migrate.apply(bodies, args),
	};
}
