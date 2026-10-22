import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse, stringify } from "yaml";
import { readOutside } from "../contract.ts";

// The lockfile is pnpm 11.3's own, for a project that ran `pnpm add @x/grant@1.2.0` (it is the
// fixture app-output's lockfile module is tried on).
const lock = readFileSync(join(import.meta.dirname, "fixtures", "staging-lock.yaml"), "utf8");
const integrity = parse(lock).packages["@x/grant@1.2.0"].resolution.integrity as string;

/** The manifest the lockfile's package was published with, declaring itself a feature. */
const manifest = {
	name: "@x/grant",
	version: "1.2.0",
	exports: { "./module": "./dist/module.js" },
	dependencies: { "jose-lite": "^1.0.0", "real-alias": "npm:real-lib@^1.0.0" },
	optionalDependencies: { "fast-path": "^2.0.0" },
	peerDependencies: { "@o3co/auth-provider-oauth": "^0.19.0", zod: "^4.6.0" },
	authProvider: { format: 1, kind: "feature", needs: ["@mod/tokens"] },
};

const release = {
	version: "0.19.0",
	zod: "4.6.7",
	bundleOf: (module: string) =>
		module.startsWith("@mod/") ? "@o3co/auth-provider-oauth" : undefined,
};

/** A project as pnpm lays one out: the package in its store, linked from `node_modules`. */
function project(
	options: {
		manifest?: Record<string, unknown>;
		files?: Record<string, string>;
		lock?: string;
		lay?: (root: string, stored: string) => void;
		npmrc?: string;
	} = {},
) {
	const root = mkdtempSync(join(tmpdir(), "outside-"));
	writeFileSync(join(root, "pnpm-lock.yaml"), options.lock ?? lock);
	writeFileSync(join(root, ".npmrc"), options.npmrc ?? "registry=http://127.0.0.1:4873/\n");
	const stored = join(
		root,
		"node_modules",
		".pnpm",
		"@x+grant@1.2.0",
		"node_modules",
		"@x",
		"grant",
	);
	mkdirSync(stored, { recursive: true });
	const files = { "package.json": JSON.stringify(options.manifest ?? manifest), ...options.files };
	for (const [file, text] of Object.entries(files)) writeFileSync(join(stored, file), text);
	mkdirSync(join(root, "node_modules", "@x"), { recursive: true });
	if (options.lay) options.lay(root, stored);
	else symlinkSync(stored, join(root, "node_modules", "@x", "grant"));
	return root;
}

const read = (root: string, names = ["@x/grant"]) => readOutside(root, names, release).outside;
const refused = (root: string, why: string | RegExp, names?: string[]) =>
	expect(() => read(root, names)).toThrow(why);

describe("a package outside the release, read from where pnpm installed it", () => {
	it("reads its declaration, its record and its files", () => {
		const root = project({
			files: {
				"config.example": 'grant { issuer = "REPLACE-ISSUER" }\n',
				"README.md": "# grant\n",
			},
		});
		const [outside] = read(root);
		expect(outside?.declaration).toEqual({
			name: "@x/grant",
			kind: "feature",
			needs: ["@mod/tokens"],
		});
		expect(outside?.record).toEqual({
			name: "@x/grant",
			version: "1.2.0",
			integrity,
			dependencies: manifest.dependencies,
			optionalDependencies: manifest.optionalDependencies,
			peerDependencies: manifest.peerDependencies,
			peerDependenciesMeta: {},
		});
		expect(outside?.fragment).toBe('grant { issuer = "REPLACE-ISSUER" }\n');
		expect(outside?.card).toBe("# grant\n");
		expect(outside?.references).toBeUndefined();
	});

	it("maps an adapter's and a wiring's declarations, field by field", () => {
		const adapter = {
			...manifest,
			authProvider: {
				format: 1,
				kind: "adapter",
				adapts: "@mod/users",
				needs: [],
				joins: ["@mod/users", "@mod/tokens"],
			},
		};
		expect(read(project({ manifest: adapter }))[0]?.declaration).toEqual({
			name: "@x/grant",
			kind: "adapter",
			needs: [],
			adapts: "@mod/users",
			joins: ["@mod/users", "@mod/tokens"],
		});
	});

	it("reads the registries the project installs from, its default and each scope's", () => {
		expect(readOutside(project(), ["@x/grant"], release).registries).toEqual({
			default: "http://127.0.0.1:4873",
		});
		const scoped = project({
			npmrc: "registry=http://127.0.0.1:4873/\n@o3co:registry=https://o3co.example/npm/\n",
		});
		expect(readOutside(scoped, ["@x/grant"], release).registries).toEqual({
			default: "http://127.0.0.1:4873",
			scopes: { "@o3co": "https://o3co.example" },
		});
	});

	it("refuses a package whose tarball lies at another registry than the project's for it", () => {
		const other = project({
			npmrc: "registry=http://127.0.0.1:4873/\n@x:registry=https://x.example/\n",
		});
		refused(
			other,
			"@x/grant: its tarball lies at http://127.0.0.1:4873, not at its registry https://x.example",
		);
	});

	it("names every refusal at once", () => {
		const root = project({
			manifest: { ...manifest, scripts: { postinstall: "node x" }, authProvider: { format: 2 } },
		});
		refused(
			root,
			/@x\/grant: it runs postinstall when installed; @x\/grant: authProvider format 2/,
		);
	});
});

describe("refusing a name or where it lies", () => {
	it("refuses a name no npm package has, or one in the release's scopes", () => {
		refused(project(), "Not A Name is not a package name", ["Not A Name"]);
		refused(project(), "@o3co/auth-provider-oauth: a name in the release's scope", [
			"@o3co/auth-provider-oauth",
		]);
		refused(project(), "@mod/tokens: a name in the release's scope", ["@mod/tokens"]);
	});

	it("refuses a package the project's lockfile does not record from a registry", () => {
		refused(project(), "@x/other: the project does not depend on it", ["@x/other"]);
		const linked = stringify({
			...parse(lock),
			importers: {
				".": { dependencies: { "@x/grant": { specifier: "link:../g", version: "link:../g" } } },
			},
		});
		refused(project({ lock: linked }), "@x/grant: the project resolves link:../g, not a version");
	});

	it("refuses a package lying outside the project's node_modules, judged by path, not by text", () => {
		const elsewhere = mkdtempSync(join(tmpdir(), "elsewhere-"));
		writeFileSync(join(elsewhere, "package.json"), JSON.stringify(manifest));
		refused(
			project({ lay: (root) => symlinkSync(elsewhere, join(root, "node_modules", "@x", "grant")) }),
			"@x/grant: lies outside the project's node_modules",
		);
		// A sibling whose path only begins with the project's text is still outside it.
		const lay = (root: string) => {
			const sibling = `${root}-node_modules-x`;
			mkdirSync(sibling);
			writeFileSync(join(sibling, "package.json"), JSON.stringify(manifest));
			symlinkSync(sibling, join(root, "node_modules", "@x", "grant"));
		};
		refused(project({ lay }), "@x/grant: lies outside the project's node_modules");
	});

	it("refuses a file that is a link, is no file, or is over 64 KiB", () => {
		const linkedFile = (root: string, stored: string) => {
			symlinkSync(stored, join(root, "node_modules", "@x", "grant"));
			symlinkSync("/etc/hosts", join(stored, "config.example"));
		};
		refused(project({ lay: linkedFile }), "@x/grant: config.example is not a file");
		const directory = (root: string, stored: string) => {
			symlinkSync(stored, join(root, "node_modules", "@x", "grant"));
			mkdirSync(join(stored, "README.md"));
		};
		refused(project({ lay: directory }), "@x/grant: README.md is not a file");
		refused(
			project({ files: { "README.md": "x".repeat(64 * 1024 + 1) } }),
			"@x/grant: README.md is over 65536 bytes",
		);
	});

	it("refuses a manifest naming another package or version than the lockfile records", () => {
		refused(
			project({ manifest: { ...manifest, version: "1.2.1" } }),
			"@x/grant: its manifest is 1.2.1, where the lockfile records 1.2.0",
		);
		refused(
			project({ manifest: { ...manifest, name: "@x/other" } }),
			"@x/grant: its manifest names @x/other",
		);
	});

	it("refuses a manifest the project's lockfile did not resolve as it declares", () => {
		refused(
			project({
				manifest: {
					...manifest,
					dependencies: { "jose-lite": "^2.0.0", "real-alias": "npm:real-lib@^1.0.0" },
				},
			}),
			"@x/grant: jose-lite resolves 1.4.0, outside ^2.0.0",
		);
	});
});

describe("refusing a declaration", () => {
	const declaring = (authProvider: unknown, extra: Record<string, unknown> = {}) =>
		project({ manifest: { ...manifest, ...extra, authProvider } });

	it("refuses a package declaring nothing, or a format, a kind or a field it does not know", () => {
		refused(declaring(undefined), "@x/grant: declares no authProvider");
		refused(
			declaring({ format: 2, kind: "feature" }),
			"@x/grant: authProvider format 2, where 1 is read",
		);
		refused(
			declaring({ format: 1, kind: "plugin" }),
			"@x/grant: authProvider kind plugin is not one of feature, adapter, wiring",
		);
		refused(
			declaring({ format: 1, kind: "feature", needz: [] }),
			"@x/grant: authProvider holds needz, which it does not read",
		);
	});

	it("refuses a field of the wrong shape", () => {
		refused(
			declaring({ format: 1, kind: "feature", needs: "@mod/tokens" }),
			"@x/grant: authProvider needs is not a list of names",
		);
		refused(
			declaring({ format: 1, kind: "feature", optIn: "yes" }),
			"@x/grant: authProvider optIn is not true",
		);
		refused(
			declaring({ format: 1, kind: "adapter", adapts: ["@mod/users"] }),
			"@x/grant: authProvider adapts is not a name",
		);
		refused(
			declaring({ format: 1, kind: "feature", joins: [] }),
			"@x/grant: authProvider joins is not a list of names",
		);
	});

	it("refuses a package without a module to compose", () => {
		refused(
			declaring(manifest.authProvider, { exports: { ".": "./dist/index.js" } }),
			"@x/grant: exports no ./module",
		);
	});

	it("refuses an install script", () => {
		for (const script of ["preinstall", "install", "postinstall"]) {
			refused(
				declaring(manifest.authProvider, { scripts: { [script]: "node x" } }),
				`@x/grant: it runs ${script} when installed`,
			);
		}
	});
});

describe("refusing a second copy of the release or of zod", () => {
	const with_ = (extra: Record<string, unknown>) =>
		project({ manifest: { ...manifest, ...extra } });

	it("refuses the release's packages or zod among its own dependencies of any kind", () => {
		refused(
			with_({ dependencies: { ...manifest.dependencies, zod: "^4.6.0" } }),
			"@x/grant: depends on zod itself, where it is a peer",
		);
		refused(
			with_({ optionalDependencies: { "@o3co/auth-provider-base": "^0.19.0" } }),
			"@x/grant: depends on @o3co/auth-provider-base itself, where it is a peer",
		);
		refused(with_({ bundleDependencies: ["zod"] }), "@x/grant: bundles zod");
		refused(
			with_({
				bundledDependencies: true,
				dependencies: { ...manifest.dependencies, "@o3co/auth-provider-oauth": "^0.19.0" },
			}),
			/@x\/grant: bundles @o3co\/auth-provider-oauth/,
		);
	});

	it("refuses an alias naming the release's packages or zod", () => {
		refused(
			with_({ dependencies: { ...manifest.dependencies, "my-zod": "npm:zod@^4.6.0" } }),
			"@x/grant: my-zod is an alias of zod",
		);
	});

	it("refuses an optional peer of the release or zod, or a range without the release's version", () => {
		refused(
			with_({ peerDependenciesMeta: { zod: { optional: true } } }),
			"@x/grant: its peer zod is optional",
		);
		refused(
			with_({ peerDependencies: { ...manifest.peerDependencies, zod: "^4.7.0" } }),
			"@x/grant: its peer zod is ^4.7.0, without the app's 4.6.7",
		);
		refused(
			with_({
				peerDependencies: { ...manifest.peerDependencies, "@o3co/auth-provider-oauth": "^0.18.0" },
			}),
			"@x/grant: its peer @o3co/auth-provider-oauth is ^0.18.0, without the release's 0.19.0",
		);
		refused(
			with_({ peerDependencies: { "@o3co/auth-provider-oauth": "^0.19.0" } }),
			"@x/grant: zod is not its peer",
		);
	});

	it("refuses a need whose bundle is not its peer", () => {
		refused(
			with_({ peerDependencies: { zod: "^4.6.0" } }),
			"@x/grant: needs @mod/tokens, whose bundle @o3co/auth-provider-oauth is not its peer",
		);
	});
});
