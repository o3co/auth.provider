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
	readonly image:
		| {
				readonly copy: readonly string[];
				readonly after: string;
				/** How its install takes a registry's credentials, where a scope records a registry. */
				readonly mount?: string;
		  }
		| undefined;
	/** The guide's section, and the agents' index's lines, on those packages. */
	readonly guide: string;
	readonly index: string;
	/** What the guide's opening says comes with the modules listed. */
	readonly comesWith: string;
}

const recordFile = "outside-modules.json";
const scriptFile = "scripts/check-outside.mjs";
const npmrcFile = ".npmrc";
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
	comesWith:
		"What they need to run comes with them, and so do the wirings and bridges they come with.",
};

/**
 * What an app composing packages outside the release is given: their record and the script that
 * holds the lockfile to it, the release's packages (those it depends on, those an outside package
 * takes as a peer, and each of their bundles' dependencies on other bundles, all the way) and zod
 * held to one version each, no version from the last day but the release's and those let through,
 * and the check in its image. Nothing where it composes none.
 */
export function besideRelease(
	outside: OutsideModules | undefined,
	app: {
		readonly dependencies: Readonly<Record<string, string>>;
		readonly version: string;
		readonly zod: string;
		/** The integrity the release recorded of each bundle and of zod: each package held is held to it. */
		readonly integrity?: Readonly<Record<string, string>>;
		/** Each bundle's dependencies on other bundles: every one installed is held, not those named alone. */
		readonly bundles?: Readonly<Record<string, readonly string[]>>;
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
	const npmrc = npmrcOf(outside.registries);
	const release = new Map(
		Object.entries(app.dependencies).filter(([name]) => releasePackage(name)),
	);
	for (const { peerDependencies } of outside.modules) {
		for (const peer of Object.keys(peerDependencies).filter(releasePackage)) {
			if (!release.has(peer)) release.set(peer, app.version);
		}
	}
	for (const bundle of closureOf([...release.keys()], app.bundles ?? {})) {
		if (!release.has(bundle)) release.set(bundle, app.version);
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
			...(npmrc ? { [npmrcFile]: npmrc } : {}),
		},
		scripts: { [script]: `node ${scriptFile}` },
		image: {
			copy: [recordFile, scriptFile, ...(npmrc ? [npmrcFile] : [])],
			after: `pnpm ${script}`,
			// Never in a layer: the install stage reads them from where pnpm looks, for that one command.
			...(npmrc ? { mount: "--mount=type=secret,id=npmrc,target=/root/.npmrc" } : {}),
		},
		guide: guideOf(outside.modules, npmrc !== undefined),
		// Only the packages named are read: one outside the release brings no other outside it.
		comesWith:
			"What they need to run comes with them, and so do the wirings and bridges of the release's modules. A package outside the release brings no other: each wiring and adapter outside it must be listed by name, or boot refuses, naming the contract no module provides.",
		index: `\nPackages outside the release, not part of it: \`${recordFile}\` records each one as the app was generated.\n`,
	};
}

/**
 * The app's `.npmrc`: each scope recorded with a registry of its own, by the origin the record holds,
 * and no credential; none without one. A record of anything else is refused, and not told, for an
 * address may hold a secret, and a line break would write another setting.
 */
function npmrcOf({ scopes = {} }: Registries): string | undefined {
	const entries = Object.entries(scopes).sort(([a], [b]) => (a < b ? -1 : 1));
	if (entries.length === 0) return undefined;
	for (const [scope, origin] of entries) {
		if (!/^@[a-z0-9][a-z0-9._~-]*$/.test(scope) || !isOrigin(origin)) {
			throw new Error("a scoped registry's record is not a scope and an origin");
		}
	}
	return entries.map(([scope, origin]) => `${scope}:registry=${origin}/\n`).join("");
}

/** A host as `.npmrc` may hold it: nothing pnpm would expand, as `${...}`, or read otherwise. */
const originHost = /^(?:[a-z0-9.-]+|\[[0-9a-f:.]+\])(?::\d+)?$/;

const isOrigin = (text: string) => {
	try {
		const url = new URL(text);
		return /^https?:$/.test(url.protocol) && url.origin === text && originHost.test(url.host);
	} catch {
		return false;
	}
};

/** The bundles reached from those named, through each one's dependencies on other bundles; those named among them. */
function closureOf(
	named: readonly string[],
	bundles: Readonly<Record<string, readonly string[]>>,
): ReadonlySet<string> {
	const reached = new Set(named);
	// A set walked as it grows reaches each bundle's own dependencies, and a cycle ends.
	for (const bundle of reached) for (const next of bundles[bundle] ?? []) reached.add(next);
	return reached;
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

function guideOf(modules: readonly OutsideRecord[], scoped: boolean): string {
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
		...(scoped
			? [
					`\`${npmrcFile}\` names the registry of each scope recorded, by its origin, and holds no credential; commit it, and write a registry served under a path in it by hand. Keep credentials in your own \`~/.npmrc\`. The image's install stage copies \`${npmrcFile}\` and takes credentials as a build secret, so neither reaches the image the app runs in: \`docker build --secret id=npmrc,src=$HOME/.npmrc -t auth-provider .\`.`,
					"",
				]
			: []),
	].join("\n");
}
