import { readFileSync } from "node:fs";
import { stringify } from "yaml";
import { type OutsideRecord, outsideLock, type Registries } from "../lockfile/contract.ts";

/** The packages outside the release an app composes, as recorded when it is generated. */
export interface OutsideModules {
	readonly modules: readonly OutsideRecord[];
	/** The registries they, and the release's packages, are installed from. */
	readonly registries: Registries;
	/** The names let through though published within the last day, each at its recorded version alone. */
	readonly fresh?: readonly string[];
}

/** What the app is given beside its own files, where it composes packages outside the release. */
export interface Beside {
	readonly files: Readonly<Record<string, string>>;
	readonly scripts: Readonly<Record<string, string>>;
	/** What the image's install stage copies, and runs once the dependencies are installed. */
	readonly image: { readonly copy: readonly string[]; readonly after: string } | undefined;
	/** The guide's section, and the agents' index's lines, on those packages. */
	readonly guide: string;
	readonly index: string;
}

const recordFile = "outside-modules.json";
const scriptFile = "scripts/check-outside.mjs";
const script = "check:outside";
/** A day, in minutes: pnpm installs no version published since. */
const releaseAge = 1440;
const releasePackage = (name: string) => name.startsWith("@o3co/auth-provider-");

const nothing: Beside = {
	files: {},
	scripts: {},
	image: undefined,
	guide: "",
	index: "",
};

/**
 * What an app composing packages outside the release is given: their record and the script that
 * holds the lockfile to it, the release's packages (those it depends on, and those an outside
 * package takes as a peer) and zod held to one version each, no version from the last day but the
 * release's and those let through, and the check in its image. Nothing where it composes none.
 */
export function besideRelease(
	outside: OutsideModules | undefined,
	app: {
		readonly dependencies: Readonly<Record<string, string>>;
		readonly version: string;
		readonly zod: string;
		/** The integrity the release recorded of each bundle and of zod: each package held is held to it. */
		readonly integrity?: Readonly<Record<string, string>>;
	},
): Beside {
	if (outside === undefined || outside.modules.length === 0) return nothing;
	for (const m of outside.modules) {
		// Each goes into a table of the guide: only the text a package name, a version and an integrity are made of.
		if (
			!/^[@a-z0-9._~/-]+$/.test(m.name) ||
			!/^[0-9A-Za-z.+-]+$/.test(m.version) ||
			!/^sha(256|384|512)-[A-Za-z0-9+/]+=*$/.test(m.integrity)
		) {
			throw new Error(`${m.name}: its record is not a package name, version and integrity`);
		}
	}
	for (const name of outside.fresh ?? []) {
		if (!outside.modules.some((m) => m.name === name))
			throw new Error(`${name}: let through as fresh, but not recorded`);
	}
	const release = new Map(
		Object.entries(app.dependencies).filter(([name]) => releasePackage(name)),
	);
	for (const { peerDependencies } of outside.modules) {
		for (const peer of Object.keys(peerDependencies).filter(releasePackage)) {
			if (!release.has(peer)) release.set(peer, app.version);
		}
	}
	const held = [...release.keys()].sort();
	const fresh = (outside.fresh ?? []).map(
		(name) => `${name}@${outside.modules.find((m) => m.name === name)?.version}`,
	);
	const settings = {
		overrides: {
			...Object.fromEntries(held.map((name) => [name, release.get(name)])),
			zod: app.zod,
		},
		minimumReleaseAge: releaseAge,
		minimumReleaseAgeExclude: [...held, ...fresh.sort()],
	};
	const record = {
		modules: outside.modules,
		registries: outside.registries,
		held: heldIntegrities([...held, "zod"], app.integrity ?? {}),
	};
	return {
		files: {
			[recordFile]: `${JSON.stringify(record, null, "\t")}\n`,
			// The script holds what it uses: it loads nothing of the install it checks.
			[scriptFile]: readFileSync(outsideLock.script, "utf8"),
			"pnpm-workspace.yaml": stringify(settings),
		},
		scripts: { [script]: `node ${scriptFile}` },
		image: { copy: [recordFile, scriptFile], after: `pnpm ${script}` },
		guide: guideOf(outside.modules),
		index: `\nPackages outside the release, not part of it: \`${recordFile}\` records each one as the app was generated.\n`,
	};
}

/** The integrity of each package the app holds to one copy, as the release records it; refuses one it does not. */
function heldIntegrities(names: readonly string[], recorded: Readonly<Record<string, string>>) {
	const missing = names.filter((name) => typeof recorded[name] !== "string");
	if (missing.length > 0) {
		throw new Error(
			`${missing.join(", ")}: held to one copy, but the release records no integrity of it`,
		);
	}
	return Object.fromEntries([...names].sort().map((name) => [name, recorded[name] as string]));
}

function guideOf(modules: readonly OutsideRecord[]): string {
	return [
		"",
		"## Packages outside this release",
		"",
		`These packages are not part of the release and not covered by its conformance. The app was generated with each one as \`${recordFile}\` records it:`,
		"",
		"| Package | Version | Integrity |",
		"|---|---|---|",
		...modules.map((m) => `| \`${m.name}\` | \`${m.version}\` | \`${m.integrity}\` |`),
		"",
		`After the first \`pnpm install\`, run \`pnpm ${script}\` and commit \`pnpm-lock.yaml\`: it holds the lockfile to that record, and the image runs it after installing. \`pnpm-workspace.yaml\` holds the release's packages and zod to one version each, and \`held\` in \`${recordFile}\` each to the integrity the release recorded of it. When upgrading the release, generate the app again with the new release's \`create-auth-provider\` and take the overrides, \`held\` and \`${scriptFile}\` from it: the overrides and \`held\` move together, and a check older than the record may not read all of it. A version published within the last day is not installed, but for those \`minimumReleaseAgeExclude\` names.`,
		"",
	].join("\n");
}
