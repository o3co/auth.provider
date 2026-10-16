import type { Reading } from "@mod/metrics";

export const contentType = "text/plain; version=0.0.4; charset=utf-8";

/** The names a reading takes in the text: a histogram's own and its derived ones. */
const namesOf = (r: Reading) =>
	r.kind === "histogram"
		? [r.name, `${r.name}_bucket`, `${r.name}_sum`, `${r.name}_count`]
		: [r.name];

/** Why each reading cannot be written in the text, given the names something else takes. */
export function unwritable(
	readings: readonly Reading[],
	taken: readonly string[],
): { name: string; reason: string }[] {
	// How many readings take each name, derived ones included.
	const uses = Map.groupBy(readings.flatMap(namesOf), (n) => n);
	const shared = (n: string) => (uses.get(n)?.length ?? 0) > 1;
	return readings.flatMap((r) => {
		const reasons: string[] = [];
		if (r.kind === "histogram" && r.labels.includes("le")) {
			reasons.push("a histogram label is named le");
		}
		const names = namesOf(r);
		if (names.some((n) => taken.includes(n))) reasons.push("a name it takes is the process's");
		if (names.some(shared)) reasons.push("a name it takes is another instrument's");
		return reasons.map((reason) => ({ name: r.name, reason }));
	});
}

/** Help text: a backslash and a line feed escaped, so no help breaks its line. */
const escaped = (s: string) => s.replaceAll("\\", "\\\\").replaceAll("\n", "\\n");
/** A label value: also the double quote that would close it. */
const quoted = (s: string) => `"${escaped(s).replaceAll('"', '\\"')}"`;

function labelled(labels: Readonly<Record<string, string>>, le?: string): string {
	const pairs = Object.entries(labels).map(([k, v]) => `${k}=${quoted(v)}`);
	if (le !== undefined) pairs.push(`le=${quoted(le)}`);
	return pairs.length > 0 ? `{${pairs.join(",")}}` : "";
}

/** A counter or a gauge: one value per series. */
const valueLines = (r: Exclude<Reading, { kind: "histogram" }>) =>
	r.series.map((s) => `${r.name}${labelled(s.labels)} ${s.value}`);

/** A histogram: per series, its cumulative buckets, then `+Inf`, sum and count. */
const histogramLines = (r: Extract<Reading, { kind: "histogram" }>) =>
	r.series.flatMap((s) => [
		...r.buckets.map((b, i) => `${r.name}_bucket${labelled(s.labels, String(b))} ${s.counts[i]}`),
		`${r.name}_bucket${labelled(s.labels, "+Inf")} ${s.count}`,
		`${r.name}_sum${labelled(s.labels)} ${s.sum}`,
		`${r.name}_count${labelled(s.labels)} ${s.count}`,
	]);

/** The readings in the Prometheus text format, version 0.0.4. */
export function textOf(readings: readonly Reading[]): string {
	const lines = readings.flatMap((r) => [
		`# HELP ${r.name} ${escaped(r.help)}`,
		`# TYPE ${r.name} ${r.kind}`,
		...(r.kind === "histogram" ? histogramLines(r) : valueLines(r)),
	]);
	return lines.length > 0 ? `${lines.join("\n")}\n` : "";
}
