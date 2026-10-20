import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { completed, composed, full, needed, optIns } from "../src/contract.ts";
import { completedWith, declaredIn } from "../src/declared.ts";

// These tests read the whole workspace, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

// How modules are completed is tried on a fixture; here, only that the workspace's own
// declarations are what completes them, so adding a wiring or a bridge changes no test.
it("completes modules with what the workspace's own wirings and bridges declare", () => {
	const declared = declaredIn(join(import.meta.dirname, "..", "..", "..", ".."));
	for (const given of [
		["@mod/http", "@mod/refresh"],
		["@mod/tokens", "@mod/subject-revocation"],
		["@mod/tokens", "@mod/code-grant"],
	]) {
		expect(completed(given)).toEqual(completedWith(declared, given));
	}
	// Each given module the workspace wires comes with its wiring, whichever package that is.
	const given = ["@mod/session", "@mod/tokens", "@mod/code-grant"];
	const wirings = given.flatMap((name) => declared.wirings.get(name) ?? []);
	expect(wirings).not.toEqual([]);
	expect(completed(given)).toEqual(expect.arrayContaining([...wirings, "@mod/session-tokens"]));
}, 30_000);

// The axis rule full and the patterns follow: an owner a declared default replaces is that default.
it("composes the default that replaces an owner in the owner's place, needed or completed", () => {
	const needs = needed(["@mod/logout"]);
	expect(needs).toContain("@mod/session-lifecycle");
	expect(needs).not.toContain("@mod/session");
	const named = completed(["@mod/session", "@mod/tokens", "@mod/code-grant"]);
	expect(named).toEqual(
		expect.arrayContaining(["@mod/session-lifecycle", "@mod/session-store", "@mod/session-tokens"]),
	);
	expect(named).not.toContain("@mod/session");
	// Named as its default, session still joins its bridges: tokens die with a session's close.
	const byDefault = completed([
		"@mod/session-lifecycle",
		"@mod/tokens",
		"@mod/code-grant",
		"@mod/users",
		"@mod/webauthn",
	]);
	expect(byDefault).toEqual(
		expect.arrayContaining([
			"@mod/session-tokens",
			"@mod/subject-attributes",
			"@mod/passkey-registration",
		]),
	);
	expect(byDefault).not.toContain("@mod/session");
	// An owner with no module of its own is its default too, as in full: upstreams is federation.
	expect(needed(["@mod/idp-oidc"])).toContain("@mod/federation");
	// Only a declared default replaces: the store keeps its own module beside its one adapter.
	expect(needed(["@mod/rate-limit"])).not.toContain("@mod/redis");
}, 60_000);

const root = join(import.meta.dirname, "..", "..", "..", "..");
const manifests = (
	JSON.parse(
		execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], { cwd: root, encoding: "utf8" }),
	) as { path: string }[]
).map(({ path }) => JSON.parse(readFileSync(join(path, "package.json"), "utf8")));

it("has every bridge and wiring name only modules the workspace has", () => {
	const names = new Set(manifests.map((manifest) => manifest.name as string));
	for (const manifest of manifests) {
		const named = [...(manifest.joins ?? []), ...(manifest.wires ? [manifest.wires] : [])];
		expect(
			named.filter((name: string) => !names.has(name)),
			manifest.name,
		).toEqual([]);
	}
});

// How full is derived is tried on a fixture; here, that the workspace's own declarations make it.
it("composes the workspace's full template: each axis's default, no owner it replaces, and no feature that opts in", () => {
	const composed = full();
	expect(composed).toEqual(
		expect.arrayContaining(["@mod/redis", "@mod/audit-http", "@mod/log-stdout"]),
	);
	expect(composed).not.toContain("@mod/store");
	expect(optIns()).toEqual(expect.arrayContaining(["@mod/dpop", "@mod/mtls", "@mod/device-grant"]));
	// A feature that opts in comes only where a composed module needs it to run.
	const needed = (name: string) =>
		composed.some((other) => {
			const manifest = manifests.find((m) => m.name === other);
			return Object.keys(manifest?.dependencies ?? {}).includes(name);
		});
	expect(composed.filter((name) => optIns().includes(name) && !needed(name))).toEqual([]);
	expect(full(["@mod/dpop"])).toContain("@mod/dpop");
});

// An axis whose owner has no module: a module that needs only the owner gets the owner's default adapter.
it("composes federation, upstreams' default, with the wirings of what it needs, where a selection needs upstreams alone", () => {
	const selections = [
		{ features: { login: ["@mod/upstreams"] } },
		{ features: {}, add: ["@mod/idp-apple"] },
		{ features: {}, add: ["@mod/federation-grants"] },
	];
	for (const selection of selections) {
		expect(composed(selection), JSON.stringify(selection)).toEqual(
			expect.arrayContaining([
				"@mod/federation",
				"@mod/upstream-round-trip-store",
				"@mod/upstream-handoff-store",
			]),
		);
	}
});

it("composes federation, once, wherever a composed module reaches it: in full, and with an IdP or federation grants added", () => {
	for (const add of [[], ["@mod/idp-github"], ["@mod/federation-grants"]]) {
		const composed = full(add);
		expect(
			composed.filter((name) => name === "@mod/federation"),
			add.join(),
		).toHaveLength(1);
		// upstreams is a contract alone: composing it means composing what serves it.
		expect(composed, add.join()).not.toContain("@mod/upstreams");
		for (const name of add) expect(composed, name).toContain(name);
	}
}, 30_000);

it("composes mfa wherever a factor kind is added alone, so a kind is never composed without what asks it", () => {
	for (const kind of [
		"@mod/mfa-totp",
		"@mod/mfa-recovery",
		"@mod/mfa-webauthn",
		"@mod/mfa-email",
	]) {
		expect(needed([kind]), kind).toContain("@mod/mfa");
	}
}, 30_000);
