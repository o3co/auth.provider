import type { Log } from "@mod/kernel";
import type { Reading } from "./contract.ts";
import type { Counter, Histogram, Instrument, Labels, Recorder, Spec } from "./instrument.ts";

const NAME = /^[a-z][a-z0-9_]*$/;
const named = (value: unknown) => typeof value === "string" && NAME.test(value);

/** What makes an instrument unusable, one reason each; none when it is sound. */
export function problemsOf(instrument: Instrument): string[] {
	const { spec } = instrument;
	const problems: string[] = [];
	if (!named(spec.name)) problems.push("the name is not [a-z][a-z0-9_]*");
	if (typeof spec.help !== "string") problems.push("the help is not a string");
	for (const [label, values] of Object.entries(spec.labels)) {
		if (!named(label)) {
			problems.push("a label name is not [a-z][a-z0-9_]*");
		} else if (
			!Array.isArray(values) ||
			values.length === 0 ||
			values.some((v) => typeof v !== "string") ||
			new Set(values).size !== values.length
		) {
			problems.push(`the label ${label} needs distinct string values, at least one`);
		}
	}
	if (instrument.kind === "histogram") {
		const b: unknown = instrument.spec.buckets;
		const increasing =
			Array.isArray(b) &&
			b.length > 0 &&
			b.every((x, i) => Number.isFinite(x) && (i === 0 || x > b[i - 1]));
		if (!increasing) problems.push("the buckets are not finite and strictly increasing");
	}
	return problems;
}

/** Whether `labels` holds each declared label once, with a value in its set, and nothing else. */
export function declared(spec: Spec<string>, labels: unknown): labels is Labels<string> {
	const names = Object.keys(spec.labels);
	return (
		typeof labels === "object" &&
		labels !== null &&
		Object.keys(labels).length === names.length &&
		names.every(
			(n) =>
				Object.hasOwn(labels, n) &&
				spec.labels[n]?.includes((labels as Record<string, unknown>)[n] as string),
		)
	);
}

/** A counter's value is its sum; a histogram also keeps its cumulative counts, the last for all. */
type Entry = { readonly labels: Labels<string>; sum: number; readonly counts: number[] };

/** One instrument's series, recorded within its declared label values only. */
export function kept(
	instrument: Counter | Histogram,
	log: Log,
): { record: Recorder; read: () => Reading; sample: () => Promise<Reading> } {
	const { spec } = instrument;
	const names = Object.freeze(Object.keys(spec.labels));
	const buckets = instrument.kind === "histogram" ? instrument.spec.buckets : [];
	// Every bucket's upper bound, then one for all; a recorded value is always finite.
	const bounds = [...buckets, Number.POSITIVE_INFINITY];
	const fresh = (values: readonly string[]): Entry => ({
		labels: Object.freeze(Object.fromEntries(names.map((n, i) => [n, values[i] as string]))),
		sum: 0,
		counts: Array<number>(bounds.length).fill(0),
	});
	const series = new Map<string, Entry>();
	let warned = false;
	const drop = () => {
		if (warned) return;
		warned = true;
		// The name only: the value dropped may come from a request.
		log.warn("metrics.dropped", { instrument: spec.name });
	};
	const record: Recorder = (labels, value) => {
		const fits =
			instrument.kind === "counter" ? Number.isFinite(value) && value >= 0 : Number.isFinite(value);
		if (!fits || !declared(spec, labels)) return drop();
		const values = names.map((n) => labels[n] as string);
		const key = JSON.stringify(values);
		const entry = series.get(key) ?? fresh(values);
		if (!series.has(key)) series.set(key, entry);
		entry.sum += value;
		const { counts } = entry;
		// Cumulative: every bucket at or above the value.
		bounds.forEach((bound, i) => {
			if (value <= bound) counts[i] = (counts[i] ?? 0) + 1;
		});
	};
	const read = (): Reading => {
		const head = { name: spec.name, help: spec.help, labels: names };
		const all = [...series.values()];
		if (instrument.kind === "counter") {
			const list = all.map((e) => Object.freeze({ labels: e.labels, value: e.sum }));
			return Object.freeze({ kind: "counter", ...head, series: Object.freeze(list) });
		}
		const list = all.map((e) =>
			Object.freeze({
				labels: e.labels,
				counts: Object.freeze([...e.counts]),
				sum: e.sum,
				count: e.counts[buckets.length] as number,
			}),
		);
		return Object.freeze({ kind: "histogram", ...head, buckets, series: Object.freeze(list) });
	};
	return { record, read, sample: async () => read() };
}
