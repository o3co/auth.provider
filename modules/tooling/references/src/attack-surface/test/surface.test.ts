import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Pkg } from "@mod/guard-imports";
import { expect, it, vi } from "vitest";
import { packages, root } from "../../../test/root.ts";
import { coverage } from "../coverage.ts";
import {
	answersHead,
	attackSurfaceFile,
	attackSurfaceIn,
	attackSurfaceOf,
	destinationByName,
	destinationCandidate,
	looseningByName,
	looseningCandidate,
	privateReachOf,
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
	destinations: [],
	notDestinations: [],
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

it("lists each route that takes cross-origin requests, so turning CORS on for one changes the reference", () => {
	const input = (cors: boolean): SurfaceInput => ({
		routes: [{ ...route, method: "POST", path: "/token", cors }],
		settings: [],
		packages: [],
		composed: [],
		internalBy: [],
		coverage: empty,
	});
	expect(attackSurfaceOf(input(true))).toContain("- POST `/token` (`@mod/r`)");
	expect(attackSurfaceOf(input(false))).not.toContain("- POST `/token` (`@mod/r`)");
});

it("lists destinations by their names and the coverage's, the coverage's with where they reach", () => {
	expect(
		["a.url", "a.keys-url", "a.redirect-uri", "a.token-endpoint", "a.hosts"].map(destinationByName),
	).toEqual([true, true, true, true, true]);
	expect(["mail-smtp.host", "a.api", "a.issuer"].map(destinationByName)).toEqual([
		false,
		false,
		false,
	]);
	expect(["mail-smtp.host", "a.api", "a.issuer", "a.discovery"].map(destinationCandidate)).toEqual([
		true,
		true,
		true,
		true,
	]);
	const reference = attackSurfaceOf({
		routes: [],
		settings: [{ key: "x.host", owner: "@mod/x" }],
		packages: [],
		composed: [],
		internalBy: [],
		coverage: { ...empty, destinations: [{ key: "x.host", reaches: "the relay" }] },
	});
	expect(reference).toContain("| `x.host` | `@mod/x` |  | the relay |");
});

it("holds, committed, the reference generated from the workspace as it is now", async () => {
	expect(readFileSync(attackSurfaceFile(root), "utf8")).toBe(
		attackSurfaceOf(await attackSurfaceIn(root, packages)),
	);
});

it("classifies every setting whose name could weaken a guarantee, and every one the security model names as a choice", async () => {
	const { settings } = await attackSurfaceIn(root, packages);
	const keys = new Set(settings.map((s) => s.key));
	/** The nearest key a setting row holds: a key written below a map (`a.<name>.b`) is the map's row. */
	const nearest = (key: string): string | undefined => {
		for (let at = key; ; at = at.slice(0, at.lastIndexOf("."))) {
			if (keys.has(at)) return at;
			if (!at.includes(".")) return undefined;
		}
	};
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
	const chosen = [...model.matchAll(/`([a-z][a-z0-9-]*(?:\.[a-z0-9<>-]+)+) = [^`]+`/g)]
		.map((m) => nearest(m[1] as string))
		.filter((key) => key !== undefined);
	const leftToYou = model
		.split(/\n(?=- \*\*)/)
		.filter((part) => part.startsWith("- **Left to you:**"))
		.flatMap((part) => [...part.matchAll(/`([a-z][a-z0-9.<>-]+)`/g)].map((m) => m[1] as string))
		.filter((key) => key.includes("."))
		.map(nearest)
		.filter((key) => key !== undefined);
	const unclassified = [...new Set([...candidates, ...chosen, ...leftToYou])].filter(
		(key) => !classified.has(key),
	);
	expect(unclassified, "classify each in coverage.ts").toEqual([]);
	// A key written below a map counts as the map's: `federation.idps`, for `upstream-amr`.
	expect(leftToYou).toContain("federation.idps");
	const destinations = new Set([
		...settings.filter((s) => destinationByName(s.key)).map((s) => s.key),
		...coverage.destinations.map((d) => d.key),
		...coverage.notDestinations.map((d) => d.key),
	]);
	const unplaced = settings
		.map((s) => s.key)
		.filter((key) => destinationCandidate(key) && !destinations.has(key));
	expect(unplaced, "classify each destination in coverage.ts").toEqual([]);
});

it("holds the coverage to the workspace: every setting, route and runbook section it names is there", async () => {
	const { settings, routes } = await attackSurfaceIn(root, packages);
	const keys = new Set(settings.map((s) => s.key));
	const named = [
		...coverage.secrets,
		...coverage.notSecrets,
		...coverage.loosening,
		...coverage.notLoosening,
		...coverage.destinations,
		...coverage.notDestinations,
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

it("lists who may reach private addresses by their own declaration, and while it is read, by an owner's list", () => {
	const at = (name: string, manifest: Pkg["manifest"]): Pkg => ({
		name,
		dir: `/${name}`,
		manifest,
		card: undefined,
		files: [],
	});
	const owner = at("@x/policy", { narrower: { type: "Narrower", property: "internal" } });
	expect(
		privateReachOf([
			owner,
			at("@x/b", { narrower: "internal" }),
			at("@x/a", { narrower: "internal" }),
			at("@x/other", { narrower: "private" }),
			at("@x/none", {}),
		]),
	).toEqual(["@x/a", "@x/b"]);
	expect(
		privateReachOf([
			at("@x/listing", { internalBy: ["@x/listed"] }),
			at("@x/b", { narrower: "internal" }),
		]),
	).toEqual(["@x/listed"]);
	expect(
		privateReachOf([
			owner,
			at("@x/listing", { internalBy: ["@x/listed", "@x/b"] }),
			at("@x/b", { narrower: "internal" }),
		]),
	).toEqual(["@x/b", "@x/listed"]);
});
