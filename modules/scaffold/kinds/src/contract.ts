/** The kinds a package's manifest names, each the one word the product and its checks read. */
export const kinds = {
	common: "common",
	foundation: "foundation",
	capability: "capability",
	feature: "feature",
	adapter: "adapter",
	assembly: "assembly",
	wiring: "wiring",
	verification: "verification",
} as const;

export type Kind = (typeof kinds)[keyof typeof kinds];

/** Kinds from the bottom up: a kind may depend on its own level and those below. */
export const kindOrder: readonly (readonly Kind[])[] = [
	[kinds.common],
	[kinds.foundation],
	[kinds.capability],
	[kinds.feature],
	[kinds.adapter],
	[kinds.assembly, kinds.wiring, kinds.verification],
];

/** Kinds that never depend on a capability, though it sits below them. */
export const capabilityBlind: readonly Kind[] = [kinds.feature];

const levelOf = (kind: string) => kindOrder.findIndex((level) => level.some((k) => k === kind));

/** Whether a package of kind `from` may depend on one of kind `to`; never, where either is no kind. */
export function mayNeed(from: string, to: string): boolean {
	const [above, below] = [levelOf(from), levelOf(to)];
	if (above < 0 || below < 0 || below > above) return false;
	return !(to === kinds.capability && capabilityBlind.some((k) => k === from));
}
