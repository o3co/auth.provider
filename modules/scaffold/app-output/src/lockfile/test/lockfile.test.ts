import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { stringify } from "yaml";
import { type OutsideRecord, outsideLock } from "../contract.ts";

const integrity = "sha512-AAAA";
const record: OutsideRecord = {
	name: "@x/grant",
	version: "1.2.0",
	integrity,
	dependencies: { "jose-lite": "^1.0.0" },
	optionalDependencies: { "fast-path": "^2.0.0" },
	peerDependencies: { "@o3co/auth-provider-oauth": "^0.19.0", zod: "^4.6.0" },
	peerDependenciesMeta: {},
};
const overrides = { "@o3co/auth-provider-oauth": "0.19.0", zod: "4.6.7" };
const peers = "(@o3co/auth-provider-oauth@0.19.0(zod@4.6.7))(zod@4.6.7)";

/** A lockfile as pnpm writes one for an app depending on `@x/grant`, with what `change` makes of it. */
function lockOf(change: (lock: Lock) => void = () => {}): string {
	const lock: Lock = {
		lockfileVersion: "9.0",
		importers: {
			".": {
				dependencies: {
					"@x/grant": { specifier: "1.2.0", version: `1.2.0${peers}` },
					"@o3co/auth-provider-oauth": { specifier: "0.19.0", version: "0.19.0(zod@4.6.7)" },
					zod: { specifier: "4.6.7", version: "4.6.7" },
				},
			},
		},
		packages: {
			"@x/grant@1.2.0": {
				resolution: { integrity },
				peerDependencies: { "@o3co/auth-provider-oauth": "0.19.0", zod: "4.6.7" },
			},
			"@o3co/auth-provider-oauth@0.19.0": {
				resolution: { integrity: "sha512-BBBB" },
				peerDependencies: { zod: "4.6.7" },
			},
			"jose-lite@1.4.0": { resolution: { integrity: "sha512-CCCC" } },
			"zod@4.6.7": { resolution: { integrity: "sha512-DDDD" } },
		},
		snapshots: {
			[`@x/grant@1.2.0${peers}`]: {
				dependencies: {
					"@o3co/auth-provider-oauth": "0.19.0(zod@4.6.7)",
					"jose-lite": "1.4.0",
					zod: "4.6.7",
				},
			},
			"@o3co/auth-provider-oauth@0.19.0(zod@4.6.7)": { dependencies: { zod: "4.6.7" } },
			"jose-lite@1.4.0": {},
			"zod@4.6.7": {},
		},
	};
	change(lock);
	return stringify(lock);
}

type Entry = Record<string, unknown> & { resolution?: Record<string, unknown> };
interface Lock {
	lockfileVersion: string;
	importers: Record<
		string,
		{ dependencies: Record<string, { specifier: string; version: string }> }
	>;
	packages: Record<string, Entry>;
	snapshots: Record<string, Record<string, Record<string, string>>>;
}

const snapshotOf = (lock: Lock) =>
	lock.snapshots[`@x/grant@1.2.0${peers}`] as Record<string, Record<string, string>>;

describe("what an app's lockfile resolves an outside package to", () => {
	const refusals = (lock: string, records = [record]) =>
		outsideLock.refusals(lock, records, overrides);

	it("passes the lockfile pnpm writes, its peer ranges rewritten by the app's overrides", () => {
		expect(refusals(lockOf())).toEqual([]);
	});

	it("refuses where the app's importer resolves the package to another version, or not from a registry", () => {
		expect(
			refusals(
				lockOf(
					(l) =>
						((l.importers["."] as Lock["importers"]["."]).dependencies["@x/grant"] = {
							specifier: "1.2.1",
							version: "1.2.1",
						}),
				),
			),
		).toEqual(["@x/grant: the app resolves 1.2.1, not 1.2.0 as recorded"]);
		for (const version of ["link:../grant", "file:grant.tgz", "@y/grant@1.2.0"]) {
			expect(
				refusals(
					lockOf(
						(l) =>
							((l.importers["."] as Lock["importers"]["."]).dependencies["@x/grant"] = {
								specifier: version,
								version,
							}),
					),
				),
			).toEqual([`@x/grant: the app resolves ${version}, not 1.2.0 as recorded`]);
		}
	});

	it("refuses another integrity, or a resolution that is not a registry's", () => {
		expect(
			refusals(
				lockOf(
					(l) =>
						(l.packages["@x/grant@1.2.0"] = {
							...l.packages["@x/grant@1.2.0"],
							resolution: { integrity: "sha512-ZZZZ" },
						}),
				),
			),
		).toEqual(["@x/grant: integrity sha512-ZZZZ, not sha512-AAAA as recorded"]);
		expect(
			refusals(
				lockOf(
					(l) =>
						(l.packages["@x/grant@1.2.0"] = {
							...l.packages["@x/grant@1.2.0"],
							resolution: { integrity, tarball: "https://x.example/g.tgz" },
						}),
				),
			),
		).toEqual(["@x/grant: resolved from no registry"]);
	});

	it("refuses a peer range other than the recorded one with the app's overrides applied, or other peer marks", () => {
		const peered = (peerDependencies: Record<string, string>) =>
			lockOf(
				(l) =>
					(l.packages["@x/grant@1.2.0"] = { ...l.packages["@x/grant@1.2.0"], peerDependencies }),
			);
		expect(refusals(peered({ "@o3co/auth-provider-oauth": "0.19.0", zod: "^4.6.0" }))).toEqual([
			"@x/grant: peer zod is ^4.6.0, not 4.6.7 as recorded with the app's overrides",
		]);
		expect(refusals(peered({ zod: "4.6.7" }))).toEqual([
			"@x/grant: peer @o3co/auth-provider-oauth is none, not 0.19.0 as recorded with the app's overrides",
		]);
		expect(
			refusals(
				lockOf(
					(l) =>
						(l.packages["@x/grant@1.2.0"] = {
							...l.packages["@x/grant@1.2.0"],
							peerDependenciesMeta: { zod: { optional: true } },
						}),
				),
			),
		).toEqual(["@x/grant: peerDependenciesMeta is not as recorded"]);
	});

	it("refuses a dependency resolved that the record does not declare, or one it declares missing", () => {
		expect(
			refusals(
				lockOf(
					(l) =>
						(snapshotOf(l).dependencies = { ...snapshotOf(l).dependencies, "left-pad": "1.3.0" }),
				),
			),
		).toEqual(["@x/grant: depends on left-pad, which the record does not declare"]);
		expect(
			refusals(
				lockOf(
					(l) =>
						(snapshotOf(l).dependencies = {
							zod: "4.6.7",
							"@o3co/auth-provider-oauth": "0.19.0(zod@4.6.7)",
						}),
				),
			),
		).toEqual(["@x/grant: jose-lite is declared, but not resolved"]);
	});

	it("refuses a dependency resolved outside its declared range, the app's overrides applied, or not to a version", () => {
		expect(
			refusals(
				lockOf(
					(l) =>
						(snapshotOf(l).dependencies = { ...snapshotOf(l).dependencies, "jose-lite": "2.0.0" }),
				),
			),
		).toEqual(["@x/grant: jose-lite resolves 2.0.0, outside ^1.0.0"]);
		expect(
			refusals(
				lockOf(
					(l) => (snapshotOf(l).dependencies = { ...snapshotOf(l).dependencies, zod: "4.6.8" }),
				),
			),
		).toEqual(["@x/grant: zod resolves 4.6.8, outside 4.6.7"]);
		expect(
			refusals(
				lockOf(
					(l) =>
						(snapshotOf(l).dependencies = {
							...snapshotOf(l).dependencies,
							"jose-lite": "link:../jose",
						}),
				),
			),
		).toEqual(["@x/grant: jose-lite resolves link:../jose, not a version"]);
	});

	it("refuses a second version, or a second resolution, of a package the overrides hold to one", () => {
		expect(
			refusals(
				lockOf((l) => (l.packages["zod@4.6.8"] = { resolution: { integrity: "sha512-EEEE" } })),
			),
		).toEqual(["zod: 2 versions in the lockfile (4.6.7, 4.6.8), where the app holds one"]);
		expect(
			refusals(lockOf((l) => (l.snapshots["@o3co/auth-provider-oauth@0.19.0(zod@4.6.8)"] = {}))),
		).toEqual([
			"@o3co/auth-provider-oauth: 2 resolutions in the lockfile, where the app holds one",
		]);
	});

	it("refuses a package the overrides hold, reached under another name", () => {
		expect(
			refusals(
				lockOf(
					(l) => (l.snapshots["jose-lite@1.4.0"] = { dependencies: { "my-zod": "zod@4.6.7" } }),
				),
			),
		).toEqual(["zod: reached as my-zod by jose-lite@1.4.0"]);
	});

	it("refuses an override outside the range the record declares for that peer", () => {
		expect(
			outsideLock.refusals(
				lockOf(),
				[{ ...record, peerDependencies: { ...record.peerDependencies, zod: "^4.7.0" } }],
				overrides,
			),
		).toContain("@x/grant: the app holds zod at 4.6.7, outside its peer range ^4.7.0");
	});
});

describe("reading a package's record from where pnpm installed it", () => {
	it("reads the version and integrity the project's importer resolves", () => {
		expect(outsideLock.recordOf(lockOf(), "@x/grant")).toEqual({
			name: "@x/grant",
			version: "1.2.0",
			integrity,
		});
	});

	it("refuses a package the importer does not depend on, or resolves from no registry", () => {
		expect(() => outsideLock.recordOf(lockOf(), "@x/none")).toThrow(
			"@x/none: the project does not depend on it",
		);
		expect(() =>
			outsideLock.recordOf(
				lockOf(
					(l) =>
						((l.importers["."] as Lock["importers"]["."]).dependencies["@x/grant"] = {
							specifier: "link:../g",
							version: "link:../g",
						}),
				),
				"@x/grant",
			),
		).toThrow("@x/grant: the project resolves link:../g, not a version");
		expect(() =>
			outsideLock.recordOf(
				lockOf((l) => (l.packages["@x/grant@1.2.0"] = { resolution: { directory: "../g" } })),
				"@x/grant",
			),
		).toThrow("@x/grant: resolved from no registry");
	});

	it("refuses a lockfile other than pnpm's version 9", () => {
		expect(() => outsideLock.recordOf(stringify({ lockfileVersion: "6.0" }), "@x/grant")).toThrow(
			"lockfile version 6.0, where 9.0 is read",
		);
	});
});

describe("the script an app runs, the file as it ships", () => {
	/** An app's directory holding the script beside the lockfile, the record and the overrides. */
	const appWith = (lock: string) => {
		const app = mkdtempSync(join(tmpdir(), "check-outside-"));
		copyFileSync(outsideLock.script, join(app, "check-outside.mjs"));
		symlinkSync(
			join(import.meta.dirname, "..", "..", "..", "node_modules"),
			join(app, "node_modules"),
		);
		writeFileSync(join(app, "pnpm-lock.yaml"), lock);
		writeFileSync(join(app, "outside-modules.json"), JSON.stringify({ modules: [record] }));
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

	it("passes the same lockfile the module passes", () => {
		expect(run(appWith(lockOf()))).toEqual({ code: 0, out: "check:outside: ok\n" });
	});

	it("refuses with the module's words, and exits 1", () => {
		const lock = lockOf(
			(l) => (l.packages["zod@4.6.8"] = { resolution: { integrity: "sha512-EEEE" } }),
		);
		expect(run(appWith(lock))).toEqual({
			code: 1,
			out: `${outsideLock.refusals(lock, [record], overrides).join("\n")}\ncheck:outside: 1 refusal(s)\n`,
		});
	});
});
