/** What a release records of the packages an app holds to one copy, beside the index, before the index's own bundle is packed. */

import { parse } from "yaml";
import { integrityOf, type Packed, packedOf } from "../packed/packed.ts";

export { integrityOf, type Packed, packedOf };

/** The zod the workspace's lockfile holds: one version alone, from a registry, with its integrity. */
export function zodOf(lockfile: string): { version: string; integrity: string } | string {
	const packages =
		(parse(lockfile) as { packages?: Record<string, { resolution?: { integrity?: unknown } }> })
			.packages ?? {};
	const zods = Object.entries(packages).filter(([key]) => /^zod@[^@]+$/.test(key));
	if (zods.length !== 1)
		return `the lockfile holds ${zods.length} versions of zod, where one is recorded`;
	const [[key, entry]] = zods as [[string, { resolution?: { integrity?: unknown } }]];
	const integrity = entry.resolution?.integrity;
	if (typeof integrity !== "string" || !integrity.startsWith("sha512-")) {
		return "the lockfile holds no sha512 integrity of zod";
	}
	return { version: key.slice("zod@".length), integrity };
}

/**
 * The index with the integrity of every bundle it is sealed over and of zod, or why not: a bundle
 * with no tarball, a tarball naming another package or version than the release's, or a zod the
 * lockfile does not record once. The index's own bundle and the entrances are packed after, and
 * are not among `bundles`.
 */
export function sealed(
	index: { readonly version: string } & Record<string, unknown>,
	bundles: readonly string[],
	packed: readonly Packed[],
	zod: { version: string; integrity: string } | string,
): { index: Record<string, unknown> } | { problems: string[] } {
	const problems: string[] = [];
	const integrity: Record<string, string> = {};
	for (const bundle of [...bundles].sort()) {
		const found = packed.filter((p) => p.name === bundle);
		if (found.length !== 1) {
			problems.push(`${bundle}: ${found.length} tarballs, where one is sealed`);
			continue;
		}
		const [one] = found as [Packed];
		if (one.version !== index.version) {
			problems.push(
				`${bundle}: its tarball is ${one.version}, where the release is ${index.version}`,
			);
			continue;
		}
		integrity[bundle] = one.integrity;
	}
	for (const other of packed.filter((p) => !bundles.includes(p.name))) {
		problems.push(`${other.name}: a tarball of no bundle the index is sealed over`);
	}
	if (typeof zod === "string") problems.push(zod);
	if (problems.length > 0) return { problems };
	return { index: { ...index, integrity, zod } };
}
