/** What every generated project shares: the target's check and the manifest. */
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { configFiles, kernel } from "@mod/app-entries";
import { stringify } from "yaml";

/** An npm package name, scoped or not: what the app's imports and dependencies can name. */
const packageName = /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
/** The longest name npm takes for a package, its scope included. */
const longestPackageName = 214;

/** Refuses, before anything is written, a name the app could not import or depend on. */
export function namesPackages(names: readonly string[]): void {
	for (const name of names) {
		if (!packageName.test(name) || name.length > longestPackageName) {
			throw new Error(`${name} is not a package name`);
		}
	}
}

/** A reading's catch: a missing file or directory reads as `absent`, and any other failure is thrown on. */
export const missingAs =
	<T>(absent: T) =>
	(error: NodeJS.ErrnoException): T => {
		if (error.code === "ENOENT") return absent;
		throw error;
	};

/** A target that is missing or empty; one that holds anything is refused, never overwritten. */
export async function vacant(target: string): Promise<void> {
	const held = await readdir(target).catch(missingAs([]));
	if (held.length > 0) throw new Error(`${target} is not empty`);
}

/** The pnpm the workspace builds with, so the lockfile reads alike in the image; corepack checks it by its sha512. */
const pnpm =
	"pnpm@12.18.0+sha512.9d7882d5dc82147ecfc4e062aa34834e0ad0296710a1837a1115ae012127d36b7109e321ac1598a1dd0a65597681b1e99917e12ed0d749eae91187943363beb3";

/** The setting that keeps `pnpm-lock.yaml` one YAML document, and why, for the operator who reads it. */
const oneDocument = `# Keeps pnpm-lock.yaml one YAML document. Otherwise pnpm writes the pnpm that
# packageManager pins into a document of its own ahead of the lockfile, which
# GitHub's dependency graph does not read, so Dependabot raises no alert on the
# app's dependencies, and which scripts/check-outside.mjs, where the app has it,
# refuses. It also stops pnpm checking that it runs the pinned version: corepack
# runs the version packageManager pins, checked against the sha512 there.
pmOnFail: ignore
`;

/**
 * The settings every app installs under, each with why and what to do when it refuses, for the
 * operator who reads it; a value the caller gives for one of them is taken in its place.
 */
const hardening = [
	{
		key: "minimumReleaseAge",
		value: 1440,
		why: `# A version is installed only once it has been public for these minutes (1440 is
# a day), so a hijacked release can be caught before it reaches this app. A day is
# pnpm's default today; stated, so a pnpm whose default differs keeps it.
`,
	},
	{
		key: "trustPolicy",
		value: "no-downgrade",
		why: `# A version whose trust evidence is weaker than an earlier version's (published
# without the provenance or trusted publisher it had before) is refused: a sign of
# a hijacked account. pnpm reads each package's metadata from the registry for it,
# some seconds more per install. A registry mirror that drops part of that
# evidence can make pnpm refuse a sound version: install from a mirror that keeps
# it. Where a refusal stays, hold the update and look at the package first;
# trustPolicyExclude, which names a package it lets through, is the last resort.
`,
	},
	{
		key: "blockExoticSubdeps",
		value: true,
		why: `# A dependency of a dependency may come from the registry alone, never from a git
# repository or a tarball URL, which no registry check or release age covers. A
# package you add, one outside the release among them, that brings such a
# dependency is refused: replace that package.
`,
	},
] as const;

/** The project's `pnpm-workspace.yaml`: the settings given, those every app installs under, and the one keeping the lockfile one document. */
export const workspaceFile = (settings: object) => {
	const given: Record<string, unknown> = { ...settings };
	const held = hardening.map(
		({ key, value, why }) => `${why}${stringify({ [key]: key in given ? given[key] : value })}`,
	);
	for (const { key } of hardening) delete given[key];
	return `${Object.keys(given).length === 0 ? "" : `${stringify(given)}\n`}${held.join("\n")}\n${oneDocument}`;
};

/** The zod the packages take, so a section the app writes is read by the same copy. */
export const zod = "4.6.7";

/** The project's manifest, running each of `scripts` by its name; with none given, it holds no `scripts`. */
export const manifestOf = (
	dependencies: Record<string, string>,
	scripts?: Readonly<Record<string, string>>,
) =>
	`${JSON.stringify(
		{
			name: "auth-provider-app",
			private: true,
			type: "module",
			packageManager: pnpm,
			scripts,
			dependencies: { ...dependencies, zod },
		},
		null,
		"\t",
	)}\n`;

/** Fills a file of `templates/` by its `{{name}}` marks; a mark with no value stays as written. */
export async function filled(template: string, fill: Readonly<Record<string, string>>) {
	const text = await readFile(join(import.meta.dirname, "..", "templates", template), "utf8");
	return text.replace(/\{\{(\w+)\}\}/g, (all, key: string) => fill[key] ?? all);
}

export const withKernel = (modules: readonly string[]) => [
	kernel,
	configFiles,
	...modules.filter((name) => name !== kernel && name !== configFiles),
];

/** Writes every file, by its path in the project, once all are made: nothing is written for a project that fails. */
export async function writeProject(target: string, files: Readonly<Record<string, string>>) {
	for (const [path, text] of Object.entries(files)) {
		await mkdir(dirname(join(target, path)), { recursive: true });
		await writeFile(join(target, path), text);
	}
}
