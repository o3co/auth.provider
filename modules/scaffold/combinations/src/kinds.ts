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
