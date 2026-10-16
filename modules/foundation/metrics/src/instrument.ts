/** Every value each label can take; series never go beyond these. */
export type LabelSet<L extends string> = { readonly [K in L]: readonly string[] };
export type Labels<L extends string> = { readonly [K in L]: string };

export interface Spec<L extends string> {
	readonly name: string;
	readonly help: string;
	readonly labels: LabelSet<L>;
}

export interface Counter<L extends string = string> {
	readonly kind: "counter";
	readonly spec: Spec<L>;
	/** Adds `by` (1 unless given); a value metrics cannot take is dropped, never thrown. */
	add(labels: Labels<L>, by?: number): void;
}

export interface Histogram<L extends string = string> {
	readonly kind: "histogram";
	readonly spec: Spec<L> & { readonly buckets: readonly number[] };
	/** Records one value; a value metrics cannot take is dropped, never thrown. */
	observe(labels: Labels<L>, value: number): void;
}

/** A gauge's series as its read gives them, one value per label combination. */
export type GaugeRead<L extends string> = () =>
	| readonly { readonly labels: Labels<L>; readonly value: number }[]
	| Promise<readonly { readonly labels: Labels<L>; readonly value: number }[]>;

/** A value read when metrics are sampled, never recorded. */
export interface Gauge<L extends string = string> {
	readonly kind: "gauge";
	readonly spec: Spec<L>;
}

export type Instrument = Counter | Histogram | Gauge;

/** Where an instrument's records go once metrics collects it. */
export type Recorder = (labels: Readonly<Record<string, unknown>>, value: number) => void;

/** How metrics attaches its recorder to an instrument; only this package holds it. */
const attachers = new WeakMap<Instrument, (to: Recorder) => boolean>();

/** Each gauge's read, which only this package calls, under its guard. */
const reads = new WeakMap<Instrument, GaugeRead<string>>();

/** Attaches `to`; false when the instrument was not made here or another assembly has it. */
export function attach(instrument: Instrument, to: Recorder): boolean {
	return attachers.get(instrument)?.(to) ?? false;
}

export const readOf = (made: Gauge): GaugeRead<string> | undefined => reads.get(made);

/** A copy the emitter can no longer change; what is not a list stays as given, for the boot check. */
function copied<S extends Spec<string>>(spec: S): S {
	const list = (value: unknown) => (Array.isArray(value) ? Object.freeze([...value]) : value);
	return Object.freeze({
		...spec,
		labels: Object.freeze(
			Object.fromEntries(Object.entries(spec.labels).map(([name, values]) => [name, list(values)])),
		),
		...("buckets" in spec ? { buckets: list(spec.buckets) } : {}),
	});
}

/** A recorder slot: records go nowhere until metrics attaches, and only one assembly attaches. */
function slot(): { record: Recorder; attach: (to: Recorder) => boolean } {
	let target: Recorder | undefined;
	return {
		record: (labels, value) => target?.(labels, value),
		attach: (to) => {
			if (target) return false;
			target = to;
			return true;
		},
	};
}

/** Makes an instrument whose records go to its slot, and registers it so metrics can attach. */
function attachable<I extends Instrument>(make: (record: Recorder) => I): I {
	const { record, attach } = slot();
	const made = make(record);
	attachers.set(made, attach);
	return made;
}

export function counter<L extends string>(spec: Spec<L>): Counter<L> {
	return attachable<Counter<L>>((record) => ({
		kind: "counter",
		spec: copied(spec),
		add: (labels, by = 1) => record(labels, by),
	}));
}

export function histogram<L extends string>(
	spec: Spec<L> & { readonly buckets: readonly number[] },
): Histogram<L> {
	return attachable<Histogram<L>>((record) => ({
		kind: "histogram",
		spec: copied(spec),
		observe: (labels, value) => record(labels, value),
	}));
}

export function gauge<L extends string>(spec: Spec<L>, read: GaugeRead<L>): Gauge<L> {
	// A gauge records nothing; attaching only claims it for one assembly.
	const made = attachable<Gauge<L>>(() => ({ kind: "gauge", spec: copied(spec) }));
	reads.set(made, read as GaugeRead<string>);
	return made;
}
