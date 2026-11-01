import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { readBundles } from "../../contract.ts";
import { packOrder } from "./pack-order.ts";

/** What `pnpm bundles` built, read for the release: its root, the order the release packs it in, and each package's name and version. */
export function releaseOrder(root: string) {
	const out = join(root, "dist", "bundles");
	if (!existsSync(out)) return { problems: ["dist/bundles is missing; run pnpm bundles first"] };
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
	const unit = (dir: string) => {
		const { name, version } = JSON.parse(readFileSync(join(out, dir, "package.json"), "utf8"));
		return { dir, name: String(name), version: String(version) };
	};
	return {
		out,
		order,
		units: {
			first: order.first.map(unit),
			index: unit(order.index.dir),
			last: order.last.map(unit),
		},
	};
}
