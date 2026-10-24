import { join } from "node:path";
import { expect, it } from "vitest";
import { readBundles } from "../src/contract.ts";

// What ships is decided by the directory a package sits in, never by its own `private`.
it("ships ledger-wire in the user ledger's bundle, and keeps ledger-fakes in one that does not ship", () => {
	const root = join(import.meta.dirname, "..", "..", "..", "..");
	const bundles = readBundles(root);
	const bundleOf = (name: string) =>
		bundles.find((bundle) => bundle.members.some((member) => member.name === name));
	expect(bundleOf("@mod/ledger-wire")?.shipped).toBe(true);
	expect(bundleOf("@mod/ledger-wire")?.dir).toBe(bundleOf("@mod/users-http")?.dir);
	expect(bundleOf("@mod/ledger-fakes")?.shipped).toBe(false);
}, 60_000);
