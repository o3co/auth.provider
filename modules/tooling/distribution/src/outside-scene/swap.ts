/** A lockfile with zod pointed at another package's tarball on its registry, as one changing it by hand would. */
import { parse, stringify } from "yaml";

interface Entry {
	resolution?: { integrity?: unknown; tarball?: unknown };
}

/**
 * The lockfile with zod's entry pointed at another package the lockfile holds from the default
 * registry: that package's tarball at the registry's origin, and its own good integrity. Only the
 * integrity the release recorded of zod tells it apart. Answers the text and the integrity put in,
 * or why no such package is there.
 */
export function swappedZod(
	lockfile: string,
	origin: string,
): { text: string; integrity: string } | { problem: string } {
	const lock = parse(lockfile) as { packages?: Record<string, Entry> };
	const packages = lock.packages ?? {};
	const zod = Object.keys(packages).find((key) => /^zod@[^@]+$/.test(key));
	if (zod === undefined) return { problem: "the lockfile holds no zod" };
	const other = Object.entries(packages).find(
		([key, entry]) =>
			/^[a-z][^@/]*@[^@]+$/.test(key) &&
			!key.startsWith("zod@") &&
			typeof entry.resolution?.integrity === "string" &&
			entry.resolution.tarball === undefined,
	);
	if (other === undefined)
		return { problem: "the lockfile holds no other package from the registry" };
	const [key, entry] = other;
	const [name, version] = key.split("@") as [string, string];
	const integrity = entry.resolution?.integrity as string;
	packages[zod] = {
		...packages[zod],
		resolution: { integrity, tarball: `${origin}/${name}/-/${name}-${version}.tgz` },
	};
	return { text: stringify(lock), integrity };
}
