import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse, stringify } from "yaml";
import { type OutsideRecord, outsideLock } from "../contract.ts";
import { bundledCheck } from "./bundle.ts";

// The lockfiles are pnpm 11.3's own, written against a registry serving the packages of
// `registry-packages.json` (see `generate.mjs`): an app with the release's overrides, and the
// project an operator installs an outside package into.
const fixtures = join(import.meta.dirname, "fixtures");
const appLock = readFileSync(join(fixtures, "app-lock.yaml"), "utf8");
const stagingLock = readFileSync(join(fixtures, "staging-lock.yaml"), "utf8");
const manifest = (
	JSON.parse(readFileSync(join(fixtures, "registry-packages.json"), "utf8")) as Record<
		string,
		unknown
	>[]
).find((m) => m.name === "@x/grant") as Record<string, Record<string, string>>;

const integrity = parse(appLock).packages["@x/grant@1.2.0"].resolution.integrity as string;
const record: OutsideRecord = {
	name: "@x/grant",
	version: "1.2.0",
	integrity,
	dependencies: manifest.dependencies ?? {},
	optionalDependencies: manifest.optionalDependencies ?? {},
	peerDependencies: manifest.peerDependencies ?? {},
	peerDependenciesMeta: {},
};
const overrides = { "@o3co/auth-provider-oauth": "0.19.0", zod: "4.6.7" };
/** The registry the fixtures were installed from. */
const registries = { default: "http://127.0.0.1:4873" };
const peers = "(@o3co/auth-provider-oauth@0.19.0(zod@4.6.7))(zod@4.6.7)";
const grant = `@x/grant@1.2.0${peers}`;

// biome-ignore lint/suspicious/noExplicitAny: a lockfile as data, changed as each case needs
type Lock = any;
/** The app's lockfile, with what `change` makes of it. */
const changed = (change: (lock: Lock) => void, from = appLock) => {
	const lock = parse(from);
	change(lock);
	return stringify(lock);
};
const refusals = (lock: string, records = [record], held: Record<string, string> = overrides) =>
	outsideLock.refusals(lock, records, held, registries);

describe("an app's lockfile, as pnpm writes it", () => {
	it("passes: overrides rewriting peer ranges, peers in a resolution, an optional dependency, a declared alias, a registry's own tarball address", () => {
		expect(refusals(appLock)).toEqual([]);
	});

	it("refuses one resolved with other overrides than the app's", () => {
		expect(refusals(changed((l) => (l.overrides.zod = "4.6.8")))).toContain(
			"the lockfile was resolved with other overrides than the app's",
		);
	});
});

describe("the recorded package, as the app's importer resolves it", () => {
	const importer = (version: string, specifier = version) =>
		changed((l) => (l.importers["."].dependencies["@x/grant"] = { specifier, version }));

	it("refuses another version, a range, a link, a file or an alias", () => {
		expect(refusals(importer("1.2.1"))).toEqual([
			"@x/grant: the app resolves 1.2.1, not 1.2.0 as recorded",
		]);
		expect(refusals(importer(`1.2.0${peers}`, "^1.2.0"))).toEqual([
			"@x/grant: the app depends on it as ^1.2.0, not 1.2.0 as recorded",
		]);
		for (const version of ["link:../grant", "file:grant.tgz", "@y/grant@1.2.0"]) {
			expect(refusals(importer(version))).toEqual([
				`@x/grant: the app resolves ${version}, not 1.2.0 as recorded`,
			]);
		}
	});

	it("refuses another integrity, or a resolution that is no registry's", () => {
		const resolved = (resolution: unknown) =>
			changed((l) => (l.packages["@x/grant@1.2.0"].resolution = resolution));
		expect(refusals(resolved({ integrity: "sha512-ZZZZ" }))).toEqual([
			`@x/grant: integrity sha512-ZZZZ, not ${integrity} as recorded`,
		]);
		for (const resolution of [
			{ integrity, type: "directory", directory: "../g" },
			{ directory: "../g" },
		]) {
			expect(refusals(resolved(resolution))).toEqual(["@x/grant: resolved from no registry"]);
		}
		expect(refusals(resolved({ integrity, tarball: "file:g.tgz" }))).toEqual([
			"@x/grant: its tarball lies at file:g.tgz, not at its registry http://127.0.0.1:4873",
		]);
	});

	it("refuses a peer range other than the record's with the app's overrides applied, or other peer marks", () => {
		expect(
			refusals(changed((l) => (l.packages["@x/grant@1.2.0"].peerDependencies.zod = "^4.6.0"))),
		).toEqual(["@x/grant: peer zod is ^4.6.0, not 4.6.7 as recorded with the app's overrides"]);
		expect(
			refusals(
				changed(
					(l) => (l.packages["@x/grant@1.2.0"].peerDependenciesMeta = { zod: { optional: true } }),
				),
			),
		).toEqual(["@x/grant: peerDependenciesMeta is not as recorded"]);
	});

	it("refuses an override outside the peer range the record declares", () => {
		expect(
			refusals(appLock, [
				{ ...record, peerDependencies: { ...record.peerDependencies, zod: "^4.7.0" } },
			]),
		).toContain("@x/grant: the app holds zod at 4.6.7, outside its peer range ^4.7.0");
	});

	it("refuses a lockfile holding no resolution of it", () => {
		expect(refusals(changed((l) => delete l.snapshots[grant]))).toContain(
			"@x/grant: the lockfile holds no resolution of it",
		);
	});
});

describe("each resolution of the recorded package, held to what the record declares", () => {
	const snapshot = (change: (s: Lock) => void) => changed((l) => change(l.snapshots[grant]));

	it("refuses a dependency the record does not declare", () => {
		expect(refusals(snapshot((s) => (s.dependencies["left-pad"] = "1.3.0")))).toEqual([
			"@x/grant: depends on left-pad, which the record does not declare",
		]);
	});

	it("refuses a required dependency or peer not resolved, or resolved only as optional", () => {
		expect(refusals(snapshot((s) => delete s.dependencies["jose-lite"]))).toEqual([
			"@x/grant: jose-lite is declared, but not resolved as required",
		]);
		expect(
			refusals(
				snapshot((s) => {
					s.optionalDependencies["jose-lite"] = s.dependencies["jose-lite"];
					delete s.dependencies["jose-lite"];
				}),
			),
		).toEqual([
			"@x/grant: jose-lite resolves as optional, not as declared",
			"@x/grant: jose-lite is declared, but not resolved as required",
		]);
		expect(refusals(snapshot((s) => delete s.dependencies.zod))).toEqual([
			"@x/grant: zod is declared, but not resolved as required",
		]);
	});

	it("refuses an optional dependency resolved as required", () => {
		expect(
			refusals(
				snapshot((s) => {
					s.dependencies["fast-path"] = s.optionalDependencies["fast-path"];
					delete s.optionalDependencies["fast-path"];
				}),
			),
		).toEqual(["@x/grant: fast-path resolves as required, not as declared"]);
	});

	it("takes an optional declaration over a required one of its name, as npm does", () => {
		const both = { ...record, dependencies: { ...record.dependencies, "fast-path": "^1.0.0" } };
		expect(refusals(appLock, [both])).toEqual([]);
	});

	it("refuses a dependency outside its range, the app's overrides applied, or resolved to no version", () => {
		expect(refusals(snapshot((s) => (s.dependencies["jose-lite"] = "2.0.0")))).toEqual([
			"@x/grant: jose-lite resolves 2.0.0, outside ^1.0.0",
		]);
		expect(refusals(snapshot((s) => (s.dependencies["jose-lite"] = "link:../jose")))).toEqual([
			"@x/grant: jose-lite resolves link:../jose, not a version",
		]);
	});

	it("takes a declared alias to a version of the package it names, and refuses another package or an undeclared alias", () => {
		expect(refusals(snapshot((s) => (s.dependencies["real-alias"] = "fake-lib@1.1.0")))).toEqual([
			"@x/grant: real-alias resolves fake-lib@1.1.0, not an alias of real-lib",
		]);
		expect(refusals(snapshot((s) => (s.dependencies["real-alias"] = "real-lib@2.0.0")))).toEqual([
			"@x/grant: real-alias resolves 2.0.0, outside ^1.0.0",
		]);
		expect(refusals(snapshot((s) => (s.dependencies["jose-lite"] = "evil-jose@1.4.0")))).toEqual([
			"@x/grant: jose-lite resolves evil-jose@1.4.0, not jose-lite itself",
		]);
	});

	it("checks every resolution of it the lockfile holds, not the root's alone", () => {
		const second = `@x/grant@1.2.0(@o3co/auth-provider-oauth@0.19.0(zod@4.6.7))(zod@4.6.7)(extra@1.0.0)`;
		const lock = changed((l) => {
			l.snapshots[second] = structuredClone(l.snapshots[grant]);
			l.snapshots[second].dependencies["jose-lite"] = "2.0.0";
		});
		expect(refusals(lock)).toEqual(["@x/grant: jose-lite resolves 2.0.0, outside ^1.0.0"]);
	});

	it("reads its own declarations only: a dependency named as an object's property is a dependency", () => {
		const own = { ...record, dependencies: { ...record.dependencies, constructor: "^1.0.0" } };
		expect(
			refusals(
				snapshot((s) => (s.dependencies.constructor = "1.0.0")),
				[own],
			),
		).toEqual([]);
		expect(refusals(appLock, [own])).toEqual([
			"@x/grant: constructor is declared, but not resolved as required",
		]);
	});
});

describe("a package the app's overrides hold to one copy", () => {
	it("refuses a reference resolving it locally, to another version, or to another package", () => {
		expect(
			refusals(
				changed(
					(l) =>
						(l.importers["."].dependencies.zod = {
							specifier: "link:../fake-zod",
							version: "link:../fake-zod",
						}),
				),
			),
		).toEqual(["zod: the importer . resolves it to link:../fake-zod, not 4.6.7"]);
		expect(
			refusals(
				changed(
					(l) =>
						(l.snapshots["@o3co/auth-provider-oauth@0.19.0(zod@4.6.7)"].dependencies.zod =
							"fake-zod@4.6.7"),
				),
			),
		).toEqual([
			"zod: @o3co/auth-provider-oauth@0.19.0(zod@4.6.7) resolves it to fake-zod@4.6.7, not 4.6.7",
		]);
	});

	it("refuses a sole version other than the one held", () => {
		const moved = changed((l) => {
			l.packages["zod@4.6.8"] = l.packages["zod@4.6.7"];
			delete l.packages["zod@4.6.7"];
		});
		expect(refusals(moved)).toContain("zod: 4.6.8 in the lockfile, where 4.6.7 alone is held");
	});

	it("refuses a reference to it the lockfile does not resolve: no entry of it, or not that resolution", () => {
		expect(refusals(changed((l) => delete l.packages["zod@4.6.7"]))).toEqual([
			"zod: the lockfile holds no zod@4.6.7",
		]);
		const unresolved = refusals(changed((l) => delete l.snapshots["zod@4.6.7"]));
		expect(unresolved).toContain(
			"zod: the importer . resolves it to 4.6.7, which the lockfile does not resolve",
		);
		const moved = changed((l) => {
			l.snapshots["zod@4.6.8"] = l.snapshots["zod@4.6.7"];
			delete l.snapshots["zod@4.6.7"];
		});
		expect(refusals(moved)).toContain(
			"zod: the importer . resolves it to 4.6.7, which the lockfile does not resolve",
		);
	});

	it("refuses a second version or a second resolution", () => {
		expect(
			refusals(
				changed((l) => (l.packages["zod@4.6.8"] = { resolution: { integrity: "sha512-EEEE" } })),
			),
		).toEqual(["zod: 4.6.7, 4.6.8 in the lockfile, where 4.6.7 alone is held"]);
		expect(
			refusals(changed((l) => (l.snapshots["@o3co/auth-provider-oauth@0.19.0(zod@4.6.8)"] = {}))),
		).toEqual([
			"@o3co/auth-provider-oauth: 2 resolutions in the lockfile, where the app holds one",
		]);
	});

	it("refuses it reached under another name, by an importer's dependencies of any kind or by a resolution", () => {
		for (const group of ["devDependencies", "optionalDependencies"]) {
			const lock = changed(
				(l) =>
					(l.importers["."][group] = {
						"my-zod": { specifier: "npm:zod@4.6.7", version: "zod@4.6.7" },
					}),
			);
			expect(refusals(lock), group).toEqual(["zod: reached as my-zod by the importer ."]);
		}
		expect(
			refusals(
				changed(
					(l) => (l.snapshots["jose-lite@1.4.0"] = { dependencies: { "my-zod": "zod@4.6.7" } }),
				),
			),
		).toEqual(["zod: reached as my-zod by jose-lite@1.4.0"]);
	});
});

describe("where a package's tarball lies", () => {
	const tarballAt = (key: string, tarball: string) =>
		changed((l) => (l.packages[key].resolution = { ...l.packages[key].resolution, tarball }));

	it("takes a tarball at its registry's origin, under any path", () => {
		expect(refusals(tarballAt("zod@4.6.7", "http://127.0.0.1:4873/elsewhere/zod.tgz"))).toEqual([]);
	});

	it("refuses a tarball of a held or recorded package at another origin", () => {
		expect(refusals(tarballAt("zod@4.6.7", "https://evil.example/zod-4.6.7.tgz"))).toEqual([
			"zod: its tarball lies at https://evil.example, not at its registry http://127.0.0.1:4873",
		]);
		expect(refusals(tarballAt("@x/grant@1.2.0", "https://evil.example/grant.tgz"))).toEqual([
			"@x/grant: its tarball lies at https://evil.example, not at its registry http://127.0.0.1:4873",
		]);
		expect(refusals(tarballAt("zod@4.6.7", "file:zod.tgz"))).toEqual([
			"zod: its tarball lies at file:zod.tgz, not at its registry http://127.0.0.1:4873",
		]);
	});

	it("holds a scoped package to its scope's registry", () => {
		const scoped = { default: "http://127.0.0.1:4873", scopes: { "@x": "https://x.example" } };
		expect(outsideLock.refusals(appLock, [record], overrides, scoped)).toEqual([
			"@x/grant: its tarball lies at http://127.0.0.1:4873, not at its registry https://x.example",
		]);
	});
});

describe("reading a lockfile as data", () => {
	it("refuses an unknown tag, an anchor's alias, a duplicate key, another version and one over its bound", () => {
		const read = (text: string) => () => outsideLock.refusals(text, [], {}, registries);
		expect(read(`${appLock}\nextra: !evil 1\n`)).toThrow(/lockfile not read/);
		expect(read("lockfileVersion: '9.0'\na: &x {k: 1}\nb: *x\n")).toThrow(
			/Alias resolution is disabled/,
		);
		expect(read("lockfileVersion: '9.0'\nlockfileVersion: '9.0'\n")).toThrow(/lockfile not read/);
		expect(read("lockfileVersion: '6.0'\n")).toThrow("lockfile version 6.0, where 9.0 is read");
		expect(read(`lockfileVersion: '9.0'\n# ${"x".repeat(16 * 1024 * 1024)}\n`)).toThrow(
			"lockfile over 16777216 bytes",
		);
	});
});

describe("reading a package's record from the project pnpm installed it into", () => {
	it("reads the version and integrity the project's importer resolves, and its lockfile passes the record", () => {
		expect(outsideLock.recordOf(stagingLock, "@x/grant", registries)).toEqual({
			name: "@x/grant",
			version: "1.2.0",
			integrity,
		});
		expect(refusals(stagingLock, [record], {})).toEqual([]);
	});

	it("refuses a package the importer lacks, resolves to no version, or from no registry", () => {
		expect(() => outsideLock.recordOf(stagingLock, "@x/none", registries)).toThrow(
			"@x/none: the project does not depend on it",
		);
		const importer = (version: string) =>
			changed(
				(l) => (l.importers["."].dependencies["@x/grant"] = { specifier: version, version }),
				stagingLock,
			);
		expect(() => outsideLock.recordOf(importer("link:../g"), "@x/grant", registries)).toThrow(
			"@x/grant: the project resolves link:../g, not a version",
		);
		expect(() => outsideLock.recordOf(importer("@y/grant@1.2.0"), "@x/grant", registries)).toThrow(
			"@x/grant: the project resolves @y/grant@1.2.0, not a version",
		);
		const directory = changed(
			(l) => (l.packages["@x/grant@1.2.0"].resolution = { type: "directory", directory: "../g" }),
			stagingLock,
		);
		expect(() => outsideLock.recordOf(directory, "@x/grant", registries)).toThrow(
			"@x/grant: resolved from no registry",
		);
	});
});

describe("the script an app runs, the file as it ships", () => {
	/** An app's directory holding the script beside the lockfile, the record and the overrides. */
	const appWith = (lock: string) => {
		const app = mkdtempSync(join(tmpdir(), "check-outside-"));
		copyFileSync(outsideLock.script, join(app, "check-outside.mjs"));
		// What the app installed is beside the script; the script reads none of it.
		mkdirSync(join(app, "node_modules"));
		writeFileSync(join(app, "pnpm-lock.yaml"), lock);
		writeFileSync(
			join(app, "outside-modules.json"),
			JSON.stringify({ modules: [record], registries }),
		);
		writeFileSync(join(app, "pnpm-workspace.yaml"), stringify({ overrides }));
		return app;
	};
	const run = (app: string) => {
		try {
			return {
				code: 0,
				out: execFileSync("node", ["check-outside.mjs"], { cwd: app, encoding: "utf8" }),
			};
		} catch (error) {
			const failed = error as { status: number; stdout: string };
			return { code: failed.status, out: failed.stdout };
		}
	};

	it("passes the lockfile the module passes", () => {
		expect(run(appWith(appLock))).toEqual({ code: 0, out: "check:outside: ok\n" });
	});

	it("is the bundle of the module's own file, as write-check makes it", async () => {
		expect(readFileSync(outsideLock.script, "utf8")).toBe(await bundledCheck());
	});

	it("still refuses where the app's install holds a yaml and a semver of another's making", () => {
		const lock = changed(
			(l) =>
				(l.importers["."].dependencies.zod = {
					specifier: "link:../fake-zod",
					version: "link:../fake-zod",
				}),
		);
		const app = appWith(lock);
		// Each exports what the check imports, and ends the process as passed the moment it is imported:
		// the check as written, importing them, would pass; the one an app runs holds its own.
		for (const name of ["yaml", "semver"]) {
			mkdirSync(join(app, "node_modules", name));
			writeFileSync(
				join(app, "node_modules", name, "package.json"),
				JSON.stringify({ name, version: "9.9.9", type: "module", exports: "./index.js" }),
			);
			writeFileSync(
				join(app, "node_modules", name, "index.js"),
				'process.stdout.write("check:outside: ok\\n");\nprocess.exit(0);\nexport const parseDocument = () => {};\nexport default {};\n',
			);
		}
		const found = refusals(lock);
		expect(found).not.toEqual([]);
		expect(run(app)).toEqual({
			code: 1,
			out: `${found.join("\n")}\ncheck:outside: ${found.length} refusal(s)\n`,
		});
	});

	it("says why it cannot read a lockfile, and exits 1", () => {
		expect(run(appWith("lockfileVersion: '6.0'\n"))).toEqual({
			code: 1,
			out: "check:outside: lockfile version 6.0, where 9.0 is read\n",
		});
	});

	it("refuses with the module's words, and exits 1", () => {
		const lock = changed(
			(l) =>
				(l.importers["."].dependencies.zod = {
					specifier: "link:../fake-zod",
					version: "link:../fake-zod",
				}),
		);
		const found = refusals(lock);
		expect(run(appWith(lock))).toEqual({
			code: 1,
			out: `${found.join("\n")}\ncheck:outside: ${found.length} refusal(s)\n`,
		});
	});
});
