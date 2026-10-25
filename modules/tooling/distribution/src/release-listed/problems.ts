/** Whether the tarballs about to be published are those the release's lists were made of. */
import { type Packed, tarballFileOf } from "../packed/packed.ts";

/** A tarball about to be published, or one the lists were made of: what it is, and the file it is in. */
export type Filed = Pick<Packed, "name" | "version" | "integrity"> & { readonly file: string };

/**
 * Why the tarballs about to be published are not those the lists were made of (`tarballs.json`): one
 * twice over, one not in the file npm packs it as (the publish step finds the entrance by that name),
 * one in another file than listed, one of other bytes, one no list held, and one listed that is not
 * among them. Run where they are published, so what is published is what the lists cover.
 */
export function listedProblems(tarballs: readonly Filed[], listed: readonly Filed[]): string[] {
	const at = (p: Pick<Packed, "name" | "version">) => `${p.name}@${p.version}`;
	const byAt = new Map(listed.map((l) => [at(l), l]));
	const counts = Map.groupBy(tarballs, at);
	const twice = [...counts]
		.filter(([, all]) => all.length > 1)
		.map(([key, all]) => `${key}: ${all.length} tarballs`);
	const once = [...counts].flatMap(([, all]) => (all.length === 1 ? all : []));
	return [
		...twice,
		...once.flatMap((t) => {
			const npm = tarballFileOf(t.name, t.version);
			if (t.file !== npm) return [`${at(t)}: in ${t.file}, not ${npm} as npm packs it`];
			const l = byAt.get(at(t));
			if (!l) return [`${at(t)}: in no list`];
			if (l.file !== t.file) return [`${at(t)}: in ${t.file}, listed in ${l.file}`];
			return l.integrity === t.integrity
				? []
				: [`${at(t)}: another tarball than the lists were made of`];
		}),
		...listed
			.filter((l) => !counts.has(at(l)))
			.map((l) => `${at(l)}: listed, and not among the tarballs to publish`),
	];
}
