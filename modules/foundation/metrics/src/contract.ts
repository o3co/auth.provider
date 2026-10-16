import { contract, extensionPoint } from "@mod/kernel";
import type { Instrument, Labels } from "./instrument.ts";

export {
	type Counter,
	counter,
	type Gauge,
	type GaugeRead,
	gauge,
	type Histogram,
	histogram,
	type Instrument,
	type LabelSet,
	type Labels,
	type Spec,
} from "./instrument.ts";

/** The instruments each emitter made for this assembly; metrics records what they count. */
export const instruments = extensionPoint<Instrument>("metrics.instruments", {
	multiplicity: "keyed",
	keyOf: (instrument) => instrument.spec.name,
});

/** One instrument's values at the time of reading, one entry per label combination recorded. */
export type Reading =
	| {
			readonly kind: "counter";
			readonly name: string;
			readonly help: string;
			/** The declared label names. */
			readonly labels: readonly string[];
			readonly series: readonly { readonly labels: Labels<string>; readonly value: number }[];
	  }
	| {
			readonly kind: "gauge";
			readonly name: string;
			readonly help: string;
			readonly labels: readonly string[];
			/** Read when sampled only; `read()` gives none. */
			readonly series: readonly { readonly labels: Labels<string>; readonly value: number }[];
	  }
	| {
			readonly kind: "histogram";
			readonly name: string;
			readonly help: string;
			readonly labels: readonly string[];
			readonly buckets: readonly number[];
			readonly series: readonly {
				readonly labels: Labels<string>;
				/** Cumulative: one per bucket's upper bound, then one for all (equal to `count`). */
				readonly counts: readonly number[];
				readonly sum: number;
				readonly count: number;
			}[];
	  };

export interface Metrics {
	/** Every instrument, in the order collected; later records do not change what it returned. */
	read(): readonly Reading[];
	/** As `read()`, with each gauge read now; one that fails, is late or unfit has no series. */
	sample(): Promise<readonly Reading[]>;
}

export const metrics = contract<Metrics>("metrics");
