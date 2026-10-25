import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { root } from "../../../test/root.ts";
import { coverage } from "../coverage.ts";
import {
	answersHead,
	attackSurfaceFile,
	attackSurfaceIn,
	attackSurfaceOf,
	looseningByName,
	looseningCandidate,
	type SurfaceInput,
	secretByName,
} from "../surface.ts";

// These tests assemble the whole workspace, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

const empty = {
	redirects: [],
	secrets: [],
	notSecrets: [],
	loosening: [],
	notLoosening: [],
	manualTasks: [],
};
const route = { owner: "@mod/r", policies: [], cors: false };

it("answers HEAD for a GET that does not change state, and for no other", () => {
	const reading = { ...route, method: "GET", path: "/read" };
	const changing = { ...route, method: "GET", path: "/change", changesState: true };
	const posting = { ...route, method: "POST", path: "/post", changesState: true };
	expect([reading, changing, posting].map(answersHead)).toEqual([true, false, false]);
	const input: SurfaceInput = {
		routes: [reading, changing, posting],
		settings: [],
		packages: [],
		composed: [],
		internalBy: [],
		coverage: empty,
	};
	const reference = attackSurfaceOf(input);
	expect(reference).toContain("each `GET` that does not change state (1 of them)");
	expect(reference).toContain("- `/change` (`@mod/r`)");
});

it("finds secrets and weakening settings by their names, and leaves out what the coverage says is neither", () => {
	expect(
		[
			"a.secret",
			"a.password",
			"a.credential",
			"a.private-key",
			"seal.current.key",
			"a.client-secret",
			"a.previous-credential",
		].map(secretByName),
	).toEqual([true, true, true, true, true, true, true]);
	expect(
		["a.secret-encoding", "a.public-key", "a.secret-lifetime", "a.credential-header"].map(
			secretByName,
		),
	).toEqual([false, false, false, false]);
	expect(
		[
			"a.accept-volatile",
			"a.insecure-origin",
			"a.fail-mode",
			"a.on-unavailable",
			"a.subject-check",
		].map(looseningByName),
	).toEqual([true, true, true, true, true]);
	expect(["a.allow-any-public", "a.plain-internal", "a.keep-on-x"].map(looseningByName)).toEqual([
		false,
		false,
		false,
	]);
	expect(
		["a.allow-any-public", "a.plain-internal", "a.keep-on-x", "a.trusted-proxies"].map(
			looseningCandidate,
		),
	).toEqual([true, true, true, true]);
	const input: SurfaceInput = {
		routes: [],
		settings: [
			{ key: "x.password", owner: "@mod/x" },
			{ key: "x.secret", owner: "@mod/x" },
			{ key: "x.accept-any", owner: "@mod/x", default: false },
		],
		packages: [],
		composed: [],
		internalBy: [],
		coverage: { ...empty, notSecrets: [{ key: "x.password", why: "not one" }] },
	};
	const reference = attackSurfaceOf(input);
	expect(reference).toContain("| `x.secret` | `@mod/x` | by its name |");
	expect(reference).not.toContain("| `x.password` |");
	expect(reference).toContain("| `x.accept-any` | `@mod/x` | `false` |");
});

it("holds, committed, the reference generated from the workspace as it is now", async () => {
	expect(readFileSync(attackSurfaceFile(root), "utf8")).toBe(
		attackSurfaceOf(await attackSurfaceIn(root)),
	);
});

it("classifies every setting whose name could weaken a guarantee, and every one the security model names as a choice", async () => {
	const { settings } = await attackSurfaceIn(root);
	const keys = new Set(settings.map((s) => s.key));
	const classified = new Set([
		...settings.filter((s) => looseningByName(s.key) || secretByName(s.key)).map((s) => s.key),
		...coverage.loosening.map((l) => l.key),
		...coverage.notLoosening.map((l) => l.key),
		...coverage.secrets.map((l) => l.key),
		...coverage.notSecrets.map((l) => l.key),
	]);
	const candidates = settings.map((s) => s.key).filter(looseningCandidate);
	// The security model's choices: a setting written with a value, and one under "Left to you".
	const model = readFileSync(join(root, "docs", "security-model.md"), "utf8");
	const chosen = [...model.matchAll(/`([a-z][a-z0-9-]*(?:\.[a-z0-9<>-]+)+) = [^`]+`/g)].map(
		(m) => m[1] as string,
	);
	const leftToYou = model
		.split(/\n(?=- \*\*)/)
		.filter((part) => part.startsWith("- **Left to you:**"))
		.flatMap((part) => [...part.matchAll(/`([a-z][a-z0-9.<>-]+)`/g)].map((m) => m[1] as string))
		.filter((key) => keys.has(key));
	const unclassified = [...new Set([...candidates, ...chosen, ...leftToYou])].filter(
		(key) => !classified.has(key),
	);
	expect(unclassified, "classify each in coverage.ts").toEqual([]);
});

it("holds the coverage to the workspace: every setting, route and runbook section it names is there", async () => {
	const { settings, routes } = await attackSurfaceIn(root);
	const keys = new Set(settings.map((s) => s.key));
	const named = [
		...coverage.secrets,
		...coverage.notSecrets,
		...coverage.loosening,
		...coverage.notLoosening,
	];
	expect(named.map((n) => n.key).filter((key) => !keys.has(key))).toEqual([]);
	const served = new Set(routes.map((r) => `${r.method} ${r.path}`));
	expect(
		coverage.redirects.map((r) => `${r.method} ${r.path}`).filter((r) => !served.has(r)),
	).toEqual([]);
	const runbook = readFileSync(join(root, "docs", "runbook.md"), "utf8");
	const anchors = [...runbook.matchAll(/^#{2,4} (.+)$/gm)].map((m) =>
		(m[1] as string)
			.toLowerCase()
			.replaceAll(/[^a-z0-9 -]/g, "")
			.replaceAll(" ", "-"),
	);
	expect(coverage.manualTasks.map((t) => t.anchor).filter((a) => !anchors.includes(a))).toEqual([]);
});
