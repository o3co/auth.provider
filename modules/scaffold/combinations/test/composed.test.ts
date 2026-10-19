import { join } from "node:path";
import { expect, it, vi } from "vitest";
import {
	addableOf,
	completedOf,
	composedWith,
	fullWith,
	neededWith,
	optInsOf,
} from "../src/composed.ts";
import { declaredIn } from "../src/declared.ts";

// Generating and reading a workspace spawn pnpm, slow on a loaded machine.
vi.setConfig({ testTimeout: 30_000 });

const declared = declaredIn(join(import.meta.dirname, "composition"));
/** An axis owner with no module of its own, read once: reading a workspace takes a while. */
const owned = declaredIn(join(import.meta.dirname, "owner-bridge"));

it("composes a selection with what it needs to run, each axis's default where its owner is composed, then wirings and bridges", () => {
	expect(composedWith(declared, { features: { login: ["@c/app"] } })).toEqual([
		"@c/app",
		"@c/audit",
		"@c/helper",
		"@c/users",
		// The kernel comes with every composition: its axis has no module of its own to name it.
		"@c/log-stdout",
		// The store is replaced by its adapter; mail is not composed, so its adapter does not come.
		"@c/redis",
		"@c/audit-http",
		"@c/users-http",
		// What an adapter needs to run comes too.
		"@c/outbound",
	]);
});

it("takes the adapter or the owner a selection names for an axis in place of the default", () => {
	const chosen = composedWith(declared, {
		features: { login: ["@c/app"] },
		axes: { "@c/store": "@c/store", "@c/audit": "@c/audit-stdout", "@c/users": "@c/users" },
	});
	expect(chosen).toEqual([
		"@c/app",
		"@c/store",
		"@c/audit",
		"@c/helper",
		"@c/users",
		"@c/log-stdout",
		"@c/audit-stdout",
	]);
});

it("composes the full template: every foundation and feature with a module but those opting in, and each default", () => {
	expect(fullWith(declared)).toEqual([
		"@c/app",
		"@c/audit",
		"@c/extra",
		"@c/helper",
		"@c/outbound",
		"@c/users",
		"@c/audit-http",
		"@c/mail-smtp",
		"@c/redis",
		"@c/users-http",
		"@c/log-stdout",
	]);
});

it("adds any feature asked for, with its axis's default only once it is composed, and another adapter on that axis in place of the default", () => {
	const mailer = fullWith(declared, ["@c/mailer"]);
	expect(mailer).toContain("@c/mailer");
	expect(mailer).toContain("@c/mailer-wording");
	expect(fullWith(declared)).not.toContain("@c/mailer-wording");
	const own = fullWith(declared, ["@c/mailer", "@c/own-wording"]);
	expect(own).toContain("@c/own-wording");
	expect(own).not.toContain("@c/mailer-wording");
	const wired = fullWith(declared, ["@c/wired"]);
	expect(wired).toContain("@c/wired");
	expect(wired.at(-1)).toBe("@c/wired-store");
});

it("names what can be added, in code point order, each taken and nothing else", () => {
	const addable = addableOf(declared);
	expect(addable).toEqual([...addable].sort());
	expect(addable).toEqual(expect.arrayContaining(["@c/mailer", "@c/own-wording", "@c/wired"]));
	for (const name of addable) expect(() => fullWith(declared, [name]), name).not.toThrow();
	for (const name of declared.packages.keys()) {
		if (!addable.includes(name)) expect(() => fullWith(declared, [name]), name).toThrow();
	}
});

it("names the features that opt in", () => {
	expect(optInsOf(declared)).toEqual(["@c/mailer", "@c/wired"]);
});

it("refuses, naming each, what the workspace lacks, what is not a feature, and an axis or adapter that is not one", () => {
	expect(() =>
		composedWith(declared, {
			features: { login: ["@c/nope", "@c/store"] },
			axes: { "@c/app": "@c/extra", "@c/store": "@c/audit-stdout" },
			add: ["@c/checks", "@c/shapes"],
		}),
	).toThrow(
		"@c/nope: not in the workspace; @c/store: not a feature; " +
			"@c/checks: not a feature or an adapter with a module; @c/shapes: not a feature or an adapter with a module; " +
			"@c/app: not an axis's owner; @c/audit-stdout: not an adapter of @c/store",
	);
	expect(() => fullWith(declared, ["@c/checks"])).toThrow(
		"@c/checks: not a feature or an adapter with a module",
	);
});

it("brings a bridge joining an axis owner that has no module of its own, once the owner is reached", () => {
	// The owner is a contract only; its default adapter is composed in its place, and the bridge comes.
	expect(composedWith(owned, { features: { app: ["@o/app"] } })).toEqual([
		"@o/app",
		"@o/session-lifecycle",
		"@o/session-bridge",
	]);
	expect(fullWith(owned)).toEqual(["@o/app", "@o/session-lifecycle", "@o/session-bridge"]);
});

it("gives the modules named with what they need to run, wirings and bridges, and no axis default", () => {
	// The store stays its own module, and neither mail's nor the kernel's adapter comes.
	expect(neededWith(declared, ["@c/app"])).toEqual([
		"@c/app",
		"@c/store",
		"@c/audit",
		"@c/helper",
		"@c/users",
	]);
	// An adapter named comes in, and the owner it replaces goes; no other adapter comes.
	expect(neededWith(declared, ["@c/app", "@c/redis"])).toEqual([
		"@c/app",
		"@c/redis",
		"@c/audit",
		"@c/helper",
		"@c/users",
	]);
});

it("refuses, naming each, a module needed that the workspace lacks, as composing does", () => {
	expect(() => neededWith(declared, ["@c/app", "@c/nope", "@c/gone"])).toThrow(
		"@c/nope: not in the workspace; @c/gone: not in the workspace",
	);
});

it("gives, for an owner with no module of its own, the default declared to replace it, needed or completed", () => {
	const needs = neededWith(owned, ["@o/app"]);
	expect(needs).toContain("@o/session-lifecycle");
	expect(needs).not.toContain("@o/session");
	expect(completedOf(owned, ["@o/app", "@o/session"])).toContain("@o/session-lifecycle");
});

it("counts the owner an adapter named replaces for bridges, leaving the owner out", () => {
	const named = completedOf(owned, ["@o/app", "@o/session-lifecycle"]);
	expect(named).toEqual(["@o/app", "@o/session-lifecycle", "@o/session-bridge"]);
});

it("refuses an owner chosen for its own axis where it has no module, naming the choice", () => {
	expect(() =>
		composedWith(owned, { features: { app: ["@o/app"] }, axes: { "@o/session": "@o/session" } }),
	).toThrow(
		"axes.@o/session = @o/session: the owner has no module, so it cannot serve its own axis",
	);
});
