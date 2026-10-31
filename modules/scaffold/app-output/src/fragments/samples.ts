/** Entry samples: a type's example of one entry of a map its owner takes them for, written in the local layer's example only. */
import { hoconKey, isTree, type Tree, treeOf } from "./fragments.ts";

/** The file beside a type's manifest that holds its entry sample. */
export const sampleFile = "entry.example";

/** What a package declares of entry samples: the maps it takes them for, each by the contract their types are contributed to, or the contract its own sample's type is contributed to, with the sample's text. */
export interface Sampled {
	readonly name: string;
	readonly takes?: readonly { readonly map: string; readonly of: string }[];
	readonly sampleOf?: string;
	readonly sample?: { readonly from: string; readonly text: string };
}

/** One sample under its map, its entry named for its type. */
interface EntrySample {
	readonly map: string;
	readonly name: string;
	readonly tree: Tree;
}

const dotted = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;

/** The samples of the types composed, each under every map whose owner takes samples of its contract, in the packages' order; a sample no composed owner takes is left out. */
function entrySamplesOf(sampled: readonly Sampled[]): EntrySample[] {
	const maps = sampled.flatMap((s) => s.takes ?? []);
	const wrong = maps.find((m) => !dotted.test(m.map));
	if (wrong !== undefined) throw new Error(`${wrong.map}: not a dotted key a map can be at`);
	const samples: EntrySample[] = [];
	for (const { sampleOf, sample } of sampled) {
		const owners = maps.filter((m) => m.of === sampleOf);
		if (sample === undefined || owners.length === 0) continue;
		const tree = treeOf(sample.from, sample.text);
		if (!isTree(tree) || typeof tree.type !== "string" || !dotted.test(tree.type)) {
			throw new Error(`${sample.from}: not one entry's keys with its type`);
		}
		for (const { map } of owners) {
			if (samples.some((s) => s.map === map && s.name === tree.type)) {
				throw new Error(`${sample.from}: a second sample of ${tree.type} for ${map}`);
			}
			samples.push({ map, name: tree.type, tree });
		}
	}
	return samples;
}

/** A value in HOCON: an object one key a line, indented by its depth; a list or a scalar as JSON. */
const hoconValue = (value: unknown, depth: number): string =>
	isTree(value)
		? [
				"{",
				...Object.entries(value).map(
					([key, inner]) =>
						`${"\t".repeat(depth + 1)}${hoconKey(key)} = ${hoconValue(inner, depth + 1)}`,
				),
				`${"\t".repeat(depth)}}`,
			].join("\n")
		: JSON.stringify(value);

/** Each sample of the types composed as the local layer's example writes it: the entry at its map, in HOCON. */
export const sampleLines = (sampled: readonly Sampled[]): string[] =>
	entrySamplesOf(sampled).map((s) => `${s.map}.${hoconKey(s.name)} ${hoconValue(s.tree, 0)}`);
