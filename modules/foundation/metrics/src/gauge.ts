import type { Log } from "@mod/kernel";
import type { Reading } from "./contract.ts";
import { type Gauge, type Labels, readOf } from "./instrument.ts";
import { declared } from "./registry.ts";

type Series = { readonly labels: Labels<string>; readonly value: number };

/** The series a read gave, when each is declared, finite and given once; otherwise none. */
function fitting(gauge: Gauge, got: unknown): Series[] | undefined {
	if (!Array.isArray(got)) return undefined;
	const names = Object.keys(gauge.spec.labels);
	const seen = new Set<string>();
	const series: Series[] = [];
	for (const one of got as unknown[]) {
		const { labels, value } = (one ?? {}) as { labels?: unknown; value?: unknown };
		if (!Number.isFinite(value) || !declared(gauge.spec, labels)) return undefined;
		const values = names.map((n) => labels[n] as string);
		const key = JSON.stringify(values);
		if (seen.has(key)) return undefined;
		seen.add(key);
		const own = Object.fromEntries(names.map((n, i) => [n, values[i] as string]));
		series.push(Object.freeze({ labels: Object.freeze(own), value: value as number }));
	}
	return series;
}

/** Reads within `boundMs`: the series, or why there are none. */
async function bounded(
	gauge: Gauge,
	boundMs: number,
): Promise<Series[] | "failed" | "late" | "unfit"> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const late = new Promise<"late">((resolve) => {
		timer = setTimeout(() => resolve("late"), boundMs);
	});
	try {
		const read = readOf(gauge);
		// Through then, so a read that throws at once rejects like one that fails later.
		const got = await Promise.race([Promise.resolve().then(() => read?.()), late]);
		if (got === "late") return got;
		return fitting(gauge, got) ?? "unfit";
	} catch {
		return "failed";
	} finally {
		clearTimeout(timer);
	}
}

/** One gauge, read only when sampled; a read that fails, is late or unfit gives no series and a warn. */
export function sampledGauge(
	gauge: Gauge,
	log: Log,
	boundMs: number,
): { record: () => void; read: () => Reading; sample: () => Promise<Reading> } {
	const { spec } = gauge;
	const reading = (series: readonly Series[]): Reading =>
		Object.freeze({
			kind: "gauge",
			name: spec.name,
			help: spec.help,
			labels: Object.freeze(Object.keys(spec.labels)),
			series: Object.freeze(series),
		});
	return {
		record: () => {},
		read: () => reading([]),
		sample: async () => {
			const got = await bounded(gauge, boundMs);
			if (Array.isArray(got)) return reading(got);
			// The name and why only: never the error, which may hold anything.
			log.warn("metrics.unread", { instrument: spec.name, why: got });
			return reading([]);
		},
	};
}
