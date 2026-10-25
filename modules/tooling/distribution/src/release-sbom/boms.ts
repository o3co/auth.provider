/** The release's lists of what it ships (CycloneDX), as the tools write them, named for publication and checked against what it packed. */
import type { Packed } from "../release/seal.ts";

/** A CycloneDX document, as far as these functions read and write it. */
export interface Bom {
	readonly bomFormat: string;
	readonly specVersion: string;
	readonly metadata?: Record<string, unknown>;
	readonly components: readonly Component[];
	readonly dependencies?: readonly {
		readonly ref: string;
		readonly dependsOn?: readonly string[];
	}[];
	readonly [key: string]: unknown;
}

export interface Component {
	readonly type: string;
	readonly name: string;
	readonly group?: string;
	readonly version?: string;
	readonly purl?: string;
	readonly "bom-ref"?: string;
	readonly externalReferences?: readonly {
		readonly type: string;
		readonly url: string;
		readonly hashes?: readonly { readonly alg: string; readonly content: string }[];
	}[];
	readonly components?: readonly Component[];
	readonly [key: string]: unknown;
}

/** A package's purl, its scope's `@` encoded as the purl spec asks. */
const npmPurl = (name: string, version: string) =>
	`pkg:npm/${name.replace(/^@/, "%40")}@${version}`;
const tarballName = (name: string, version: string) =>
	`${name.replace(/^@/, "").replace("/", "-")}-${version}.tgz`;
const fullName = (c: Component) => (c.group ? `${c.group}/${c.name}` : c.name);
/** An npm integrity's SHA-512, as the lists write a hash: hexadecimal. */
const sha512Of = (integrity: string) =>
	Buffer.from(integrity.replace(/^sha512-/, ""), "base64").toString("hex");

/**
 * The list with each component this release packed named as npm publishes it: its purl,
 * its reference and its distribution URL, each installed from a tarball of this release, become the
 * registry's; its hash is kept. Any other component is kept as it is. Where one of the release's
 * own is not named by the path of a tarball it packed, nothing is renamed and each such is told.
 */
export function npmNamed(
	bom: Bom,
	packed: readonly Packed[],
): { readonly bom: Bom } | { readonly problems: string[] } {
	const problems: string[] = [];
	const renamed = new Map<string, string>();
	const names = new Set(packed.map((p) => p.name));
	const components = bom.components.map((c) => {
		const name = fullName(c);
		// Only a package this release packs was installed from its tarball; any other, of its scope or not, is the registry's.
		if (!names.has(name)) return c;
		const at = `${name}@${c.version}`;
		const file = tarballName(name, c.version ?? "");
		const ours = packed.some((p) => p.name === name && p.version === c.version);
		const local = `${npmPurl(name, c.version ?? "")}?vcs_url=`;
		const named = c.purl?.startsWith(local)
			? decodeURIComponent(c.purl.slice(local.length))
			: undefined;
		if (!ours || named === undefined || !named.startsWith("file:") || !named.endsWith(`/${file}`)) {
			problems.push(`${at}: its purl names no tarball this release packed (${c.purl ?? "none"})`);
			return c;
		}
		const distribution = c.externalReferences?.filter((r) => r.type === "distribution") ?? [];
		if (distribution.length !== 1 || distribution[0]?.url !== named) {
			problems.push(`${at}: its distribution URL is not its tarball's path`);
			return c;
		}
		const purl = npmPurl(name, c.version ?? "");
		if (c["bom-ref"]) renamed.set(c["bom-ref"], purl);
		const registry = `https://registry.npmjs.org/${name}/-/${c.name}-${c.version}.tgz`;
		return {
			...c,
			purl,
			"bom-ref": purl,
			externalReferences: (c.externalReferences ?? []).map((r) =>
				r.type === "distribution" ? { ...r, url: registry } : r,
			),
		};
	});
	if (problems.length > 0) return { problems };
	const ref = (r: string) => renamed.get(r) ?? r;
	const dependencies = bom.dependencies?.map((d) => ({
		...d,
		ref: ref(d.ref),
		...(d.dependsOn ? { dependsOn: d.dependsOn.map(ref) } : {}),
	}));
	return { bom: { ...bom, components, ...(dependencies ? { dependencies } : {}) } };
}

/** Each tarball the release packed that no list holds by its name, its version and its SHA-512, with a dependency entry. */
export function coverageProblems(boms: readonly Bom[], packed: readonly Packed[]): string[] {
	return packed.flatMap((p) => {
		const at = `${p.name}@${p.version}`;
		const found = boms.flatMap((b) =>
			b.components
				.filter((c) => fullName(c) === p.name && c.version === p.version)
				.map((c) => ({ c, b })),
		);
		if (found.length === 0) return [`${at}: in no list`];
		const hashed = found.filter(({ c }) =>
			(c.externalReferences ?? []).some((r) =>
				(r.hashes ?? []).some((h) => h.alg === "SHA-512" && h.content === sha512Of(p.integrity)),
			),
		);
		if (hashed.length === 0) return [`${at}: listed with another SHA-512 than its tarball's`];
		const related = hashed.some(({ c, b }) =>
			(b.dependencies ?? []).some((d) => d.ref === c["bom-ref"]),
		);
		return related ? [] : [`${at}: listed with no dependency entry`];
	});
}

/** A bundled file a manifest declares: the member's directory in its bundle, its path in the member, the packages inside. */
export interface Declared {
	readonly member: string;
	readonly file: string;
	readonly packages: readonly string[];
}

/** Each package a bundle's regions name the file of, at its version (`node_modules/.pnpm/<name>@<version>/node_modules/<name>/`). */
const heldIn = (text: string) =>
	new Map(
		[
			...text.matchAll(
				/^\/\/#region .*?node_modules\/\.pnpm\/[^/]+?@([^/@]+)\/node_modules\/((?:@[^/]+\/)?[^/]+)\//gm,
			),
		].map((m) => [m[2] as string, m[1] as string]),
	);

/**
 * The list of the components the release's bundles hold inside, which no dependency tree shows: each
 * bundle with a bundled file, the file within it, and the packages it holds at the versions its
 * regions name. A bundled file no manifest declares, a declared one in no tarball, and a package
 * held that its declaration does not name, are each told, and no list is made.
 */
export function insideBom(
	tarballs: readonly {
		readonly name: string;
		readonly version: string;
		readonly files: ReadonlyMap<string, string>;
	}[],
	declared: readonly Declared[],
): { readonly bom: Bom } | { readonly problems: string[] } {
	const problems: string[] = [];
	const at = (d: Declared) => `${d.member}/${d.file}`;
	const components = tarballs.flatMap((t) => {
		const ref = npmPurl(t.name, t.version);
		const files = [...t.files].flatMap(([path, text]) => {
			const d = declared.find((x) => `package/${at(x)}` === path);
			if (!d) {
				problems.push(`${t.name}: ${path} is bundled, and no manifest's bundledInside declares it`);
				return [];
			}
			const held = heldIn(text);
			for (const name of held.keys()) {
				if (!d.packages.includes(name)) {
					problems.push(
						`${at(d)}: holds ${name}@${held.get(name)} inside, which its manifest's bundledInside does not declare`,
					);
				}
			}
			const inside = [...held]
				.sort(([a], [b]) => a.localeCompare(b))
				.map(([name, version]) => ({
					type: "library",
					name,
					version,
					purl: npmPurl(name, version),
					"bom-ref": npmPurl(name, version),
				}));
			return [{ type: "file", name: at(d), "bom-ref": `${ref}#${at(d)}`, components: inside }];
		});
		if (files.length === 0) return [];
		const [group, name] = t.name.split("/") as [string, string];
		return [
			{
				type: "library",
				group,
				name,
				version: t.version,
				purl: ref,
				"bom-ref": ref,
				components: files,
			},
		];
	});
	const shipped = new Set(tarballs.flatMap((t) => [...t.files.keys()]));
	for (const d of declared) {
		if (!shipped.has(`package/${at(d)}`)) problems.push(`${at(d)}: declared, and in no tarball`);
	}
	if (problems.length > 0) return { problems };
	return { bom: { bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components } };
}
