import { execFileSync } from "node:child_process";
import {
	copyFileSync,
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { basename, join } from "node:path";
import { readBundles } from "../contract.ts";
import { releaseOrder } from "./order/release-order.ts";
import { packedOf, sealed, zodOf } from "./seal.ts";

/**
 * Packs every package the release publishes from `root`'s `dist/bundles` into `into`, in `packOrder`'s
 * order, the index sealed between: the tarballs and how many it is sealed over, or each problem. A
 * package in `given` (its directory → a tarball, as the registry holds it) is copied in, not packed;
 * the index is sealed over every bundle before it, given or packed, unless its own bundle is given,
 * which is refused where any bundle it seals over is not.
 */
export function packRelease(
	root: string,
	into: string,
	given: ReadonlyMap<string, string> = new Map(),
): { tarballs: string[]; sealedOver: number } | { problems: string[] } {
	const read = releaseOrder(root);
	if ("problems" in read) return { problems: read.problems };
	const { out, order } = read;
	mkdirSync(into, { recursive: true });

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
	/** A package given as the registry holds it is copied in as it is; any other is packed. */
	const take = (dir: string) => {
		const tarball = given.get(dir);
		if (tarball === undefined) return pack(dir);
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
			zodOf(readFileSync(join(root, "pnpm-lock.yaml"), "utf8")),
		);
		if ("problems" in result) return { problems: result.problems };
		writeFileSync(indexFile, JSON.stringify(result.index));
	}
	// An index taken as published seals nothing here.
	const sealedOver = given.has(order.index.dir) ? 0 : first.length;
	return { tarballs: [...first, ...order.last.map(take)], sealedOver };
}
