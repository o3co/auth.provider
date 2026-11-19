import { expect, it } from "vitest";
import { budget, pkg } from "../../../test/workspace.ts";
import { scopeOf } from "../scope.ts";

it("reads the owner an adapter serves only of the adapter kind, declaring exactly one of adapts and replaces", () => {
	const of = (name: string, manifest: Record<string, unknown>, kind: string) =>
		pkg(name, { "src/contract.ts": "export {};\n" }, manifest, kind);
	const adapter = of("@os/adapter", { adapts: "@os/owner" }, budget.adapterKind);
	const replacing = of("@os/replacing", { replaces: "@os/owner" }, budget.adapterKind);
	const both = of("@os/both", { adapts: "@os/owner", replaces: "@os/owner" }, budget.adapterKind);
	const neither = of("@os/neither", {}, budget.adapterKind);
	const feature = of("@os/feature", { adapts: "@os/owner" }, budget.featureKind);
	const scope = scopeOf([adapter, replacing, both, neither, feature], budget, () => {});
	expect([adapter, replacing, both, neither, feature].map((p) => scope.ownerServed(p))).toEqual([
		"@os/owner",
		"@os/owner",
		undefined,
		undefined,
		undefined,
	]);
});
