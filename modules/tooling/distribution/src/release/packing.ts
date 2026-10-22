import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { readBundles } from "../contract.ts";
import { packOrder } from "./pack-order.ts";
import { packedOf, sealed, zodOf } from "./seal.ts";

/**
 * Packs every package the release publishes from `root`'s `dist/bundles` into `into`, in `packOrder`'s
 * order, the index sealed between: the tarballs and how many it is sealed over, or each problem.
 */
export function packRelease(
	root: string,
	into: string,
): { tarballs: string[]; sealedOver: number } | { problems: string[] } {
	const out = join(root, "dist", "bundles");
	if (!existsSync(out)) return { problems: ["dist/bundles is missing; run pnpm bundles first"] };
	mkdirSync(into, { recursive: true });
	const declared = readBundles(root).map((bundle) => {
		const manifest = JSON.parse(readFileSync(join(bundle.dir, "package.json"), "utf8"));
		return {
			dir: basename(bundle.dir),
			shipped: bundle.shipped === true,
			index: manifest.index,
			entrances: Object.keys(manifest.entrances ?? {}),
		};
	});
	const order = packOrder(
		readdirSync(out).filter((dir) => existsSync(join(out, dir, "package.json"))),
		declared,
	);
	if ("problem" in order) return { problems: [order.problem] };

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

	const first = order.first.map(pack);
	const indexFile = join(out, order.index.dir, order.index.file);
	const result = sealed(
		JSON.parse(readFileSync(indexFile, "utf8")),
		order.first.map((dir) => JSON.parse(readFileSync(join(out, dir, "package.json"), "utf8")).name),
		first.map(packedOf),
		zodOf(readFileSync(join(root, "pnpm-lock.yaml"), "utf8")),
	);
	if ("problems" in result) return { problems: result.problems };
	writeFileSync(indexFile, JSON.stringify(result.index));
	return { tarballs: [...first, ...order.last.map(pack)], sealedOver: first.length };
}
