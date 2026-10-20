import { basename } from "node:path";

/** A member's manifest as written in the workspace: what it exports, depends on and runs. */
export interface MemberManifest {
	readonly name: string;
	/** The member's directory name within its bundle, the subpath it is offered under. */
	readonly dir: string;
	readonly exports: Readonly<Record<string, string>>;
	readonly dependencies: Readonly<Record<string, string>>;
	readonly peerDependencies?: Readonly<Record<string, string>>;
	readonly peerDependenciesMeta?: Readonly<Record<string, { readonly optional?: boolean }>>;
	readonly bin?: Readonly<Record<string, string>>;
}

/** What every bundle carries alike: the one version, and the workspace's engines and license. */
export interface Release {
	readonly version: string;
	readonly engines?: Readonly<Record<string, string>>;
	/** An SPDX expression, as the workspace states it. */
	readonly license?: string;
	/** The repository's URL, which provenance holds the publishing repository to. */
	readonly repository?: string;
	/** The workspace's copyright and license line, closing each package's README. */
	readonly notice?: string;
	/** The words every package of the release is found by on the registry. */
	readonly keywords?: readonly string[];
}

/** What a package says of itself on the registry: its description, and the words it is found by. */
export interface About {
	readonly description: string;
	readonly keywords: readonly string[];
}

/**
 * What a package says of itself, as its declaration states it: its own description, and the
 * release's keywords followed by its own, each once. Refuses a package without a description, or
 * whose keywords are not a list of words.
 */
export function aboutOf(
	name: string,
	declared: { readonly description?: unknown; readonly keywords?: unknown },
	release: Release,
): { readonly about: About } | { readonly problem: string } {
	const { description, keywords = [] } = declared;
	if (typeof description !== "string" || description.trim() === "") {
		return { problem: `${name}: states no description` };
	}
	if (!Array.isArray(keywords) || !keywords.every((word) => typeof word === "string")) {
		return { problem: `${name}: its keywords are not a list of words` };
	}
	return {
		about: { description, keywords: [...new Set([...(release.keywords ?? []), ...keywords])] },
	};
}

/** The manifest fields a package's description and keywords become; none for keywords without one. */
export const aboutFields = (about: About | undefined): Record<string, unknown> =>
	about
		? {
				description: about.description,
				...(about.keywords.length > 0 ? { keywords: about.keywords } : {}),
			}
		: {};

/** A bundle's public name: the scope's prefix and its concern directory's name. */
export const publicNameOf = (bundleDir: string) => `@o3co/auth-provider-${basename(bundleDir)}`;

/** The built file a source file becomes, with its declaration. */
const built = (memberDir: string, source: string) => {
	const path = `./${memberDir}/${source.replace(/^\.\//, "")}`;
	return { types: path.replace(/\.ts$/, ".d.ts"), default: path.replace(/\.ts$/, ".js") };
};

/**
 * A bundle's package.json: what it says of itself; each member's entries under its directory's
 * name, built; other bundles at the release's version; outside packages at the one version the
 * members state; the members' peers as each states them, optional where it says so. An outside
 * package some member requires as a peer (`required`, with its range) is a required peer here too
 * in place of a dependency, so the app holds its one copy. Refuses an outside package stated at two
 * versions, naming both.
 */
export function bundleManifest(
	bundle: {
		readonly dir: string;
		readonly members: readonly MemberManifest[];
		readonly about?: About;
	},
	release: Release,
	bundleOf: (name: string) => string | undefined,
	required: Readonly<Record<string, string>> = {},
): { readonly manifest: Record<string, unknown> } | { readonly problems: readonly string[] } {
	const own = basename(bundle.dir);
	const exports: Record<string, unknown> = {};
	const dependencies: Record<string, string> = {};
	const stated = new Map<string, { readonly version: string; readonly by: string }>();
	const peers: Record<string, string> = {};
	const optional = new Set<string>();
	const bin: Record<string, string> = {};
	const problems: string[] = [];
	for (const member of bundle.members) {
		for (const [key, source] of Object.entries(member.exports)) {
			exports[`./${member.dir}${key === "." ? "" : key.slice(1)}`] = built(member.dir, source);
		}
		for (const [name, version] of Object.entries(member.dependencies)) {
			const other = bundleOf(name);
			if (other !== undefined) {
				if (other !== own) dependencies[publicNameOf(other)] = release.version;
				continue;
			}
			const range = required[name];
			if (range !== undefined) {
				peers[name] = range;
				continue;
			}
			const before = stated.get(name);
			if (before && before.version !== version) {
				problems.push(
					`${own}: ${name} at ${before.version} (${before.by}) and ${version} (${member.name})`,
				);
			}
			if (!before) stated.set(name, { version, by: member.name });
			dependencies[name] = before?.version ?? version;
		}
		Object.assign(peers, member.peerDependencies);
		for (const [name, meta] of Object.entries(member.peerDependenciesMeta ?? {})) {
			if (meta.optional) optional.add(name);
		}
		for (const [command, source] of Object.entries(member.bin ?? {})) {
			bin[command] = built(member.dir, source).default;
		}
	}
	if (problems.length > 0) return { problems };
	const sorted = (entries: Record<string, string>) =>
		Object.fromEntries(Object.entries(entries).sort(([a], [b]) => (a < b ? -1 : 1)));
	const optionalPeers = Object.keys(peers).filter(
		(name) => optional.has(name) && required[name] === undefined,
	);
	return {
		manifest: {
			name: publicNameOf(bundle.dir),
			version: release.version,
			...aboutFields(bundle.about),
			type: "module",
			...(release.license ? { license: release.license } : {}),
			...(release.repository
				? { repository: { type: "git", url: release.repository, directory: `modules/${own}` } }
				: {}),
			...(release.engines ? { engines: release.engines } : {}),
			...(Object.keys(bin).length > 0 ? { bin } : {}),
			exports,
			dependencies: sorted(dependencies),
			...(Object.keys(peers).length > 0 ? { peerDependencies: sorted(peers) } : {}),
			...(optionalPeers.length > 0
				? {
						peerDependenciesMeta: Object.fromEntries(
							optionalPeers.sort().map((name) => [name, { optional: true }]),
						),
					}
				: {}),
		},
	};
}

/**
 * A built file with each workspace member named publicly (its bundle's name, then its directory,
 * then the entry), and in a declaration its own imports pointed at the built `.js` files. A
 * member it does not know stays as written, and is told.
 */
export function published(
	text: string,
	where: (name: string) => { readonly bundle: string; readonly dir: string } | undefined,
	kind: "js" | "d.ts",
): { readonly text: string; readonly unknown: readonly string[] } {
	const unknown = new Set<string>();
	// Only what is imported: a member's name a module holds as data stays the workspace's.
	let out = text.replace(
		/(\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(["'])(@mod\/[a-z0-9-]+)(\/[a-z0-9-]+)?\2/g,
		(whole, before: string, quote: string, name: string, entry: string | undefined) => {
			const found = where(name);
			if (!found) {
				unknown.add(name);
				return whole;
			}
			return `${before}${quote}${publicNameOf(found.bundle)}/${found.dir}${entry ?? ""}${quote}`;
		},
	);
	if (kind === "d.ts") {
		out = out.replace(/((?:from\s*|import\s*\(\s*)["'])(\.{1,2}\/[^"']*)\.ts(["'])/g, "$1$2.js$3");
	}
	return { text: out, unknown: [...unknown] };
}

/** A published package's README: what it is part of, where it is built from, and the notice. */
export function readmeOf(name: string, release: Release, directory?: string): string {
	const from = directory ? `, built from \`${directory}\`` : "";
	const where = release.repository ? ` of ${release.repository}` : "";
	const lines = [
		`# ${name}`,
		"",
		`Part of auth-provider ${release.version}${from}${where}. Its modules, settings and documentation are there.`,
		...(release.notice ? ["", release.notice] : []),
	];
	return `${lines.join("\n")}\n`;
}
