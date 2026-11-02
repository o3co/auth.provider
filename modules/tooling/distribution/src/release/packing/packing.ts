import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { releaseOrder } from "../order/release-order.ts";
import { packedOf, sealed, zodOf } from "../seal.ts";

/**
 * Packs every package the release publishes from `root`'s `dist/bundles` into `into`, in `packOrder`'s
 * order, the index sealed between, as `packWith` does with pnpm's pack.
 */
export function packRelease(
	root: string,
	into: string,
	given: ReadonlyMap<string, string> = new Map(),
): { tarballs: string[]; sealedOver: number } | { problems: string[] } {
	const read = releaseOrder(root);
	if ("problems" in read) return { problems: read.problems };
	const { out, order } = read;
	/** Packs one built package, with stdin closed so no lifecycle script reads it, answering the tarball. */
	const pack = (dir: string) => {
		const said = execFileSync("pnpm", ["pack", "--pack-destination", into], {
			cwd: join(out, dir),
			encoding: "utf8",
			stdio: ["ignore", "pipe", "inherit"],
		});
		const named = said.trim().split("\n").at(-1) ?? "";
		return named.startsWith("/") ? named : join(into, named);
	};
	const lockfile = readFileSync(join(root, "pnpm-lock.yaml"), "utf8");
	return packWith({ out, order, lockfile, into, given, pack });
}

/**
 * The packages `out` holds, packed by `pack` into `into` in the order given, the index sealed over
 * every bundle before its own: the tarballs and how many it is sealed over, or each problem. A
 * package in `given` (its directory → a tarball, as the registry holds it) is copied in, not packed,
 * and sealed over as it is; where the index's own bundle is given, nothing is sealed again, and each
 * bundle it seals over must be given too.
 */
export function packWith(p: {
	readonly out: string;
	readonly order: {
		readonly first: readonly string[];
		readonly index: { readonly dir: string; readonly file: string };
		readonly last: readonly string[];
	};
	readonly lockfile: string;
	readonly into: string;
	readonly given: ReadonlyMap<string, string>;
	readonly pack: (dir: string) => string;
}): { tarballs: string[]; sealedOver: number } | { problems: string[] } {
	const { out, order, given, into } = p;
	mkdirSync(into, { recursive: true });
	/** A package given as the registry holds it is copied in as it is; any other is packed. */
	const take = (dir: string) => {
		const tarball = given.get(dir);
		if (tarball === undefined) return p.pack(dir);
		const to = join(into, basename(tarball));
		copyFileSync(tarball, to);
		return to;
	};
	if (given.has(order.index.dir)) {
		const unsealed = order.first.filter((dir) => !given.has(dir));
		if (unsealed.length > 0) {
			return {
				problems: [
					`${order.index.dir} is given, but ${unsealed.join(", ")}, which its index seals over, not`,
				],
			};
		}
	}
	const first = order.first.map(take);
	if (!given.has(order.index.dir)) {
		const indexFile = join(out, order.index.dir, order.index.file);
		const result = sealed(
			JSON.parse(readFileSync(indexFile, "utf8")),
			order.first.map(
				(dir) => JSON.parse(readFileSync(join(out, dir, "package.json"), "utf8")).name,
			),
			first.map(packedOf),
			zodOf(p.lockfile),
		);
		if ("problems" in result) return { problems: result.problems };
		writeFileSync(indexFile, JSON.stringify(result.index));
	}
	// An index taken as published seals nothing here.
	const sealedOver = given.has(order.index.dir) ? 0 : first.length;
	return { tarballs: [...first, ...order.last.map(take)], sealedOver };
}
