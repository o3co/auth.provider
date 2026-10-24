import type { BuildContext } from "@mod/kernel";
import { instruments, type Metrics } from "./contract.ts";
import { sampledGauge } from "./gauge.ts";
import { attach } from "./instrument.ts";
import { kept, problemsOf } from "./registry.ts";

/** What a metrics provision built here takes from other modules. */
export const metricsTakes = [instruments] as const;

/** How long a sample waits on a gauge's read. */
export const gaugeBoundMs = 2000;

/** Metrics of one assembly, reading each gauge within `boundMs`. */
export const metricsBy =
	(boundMs: number) =>
	async (c: BuildContext<unknown>): Promise<Metrics> => {
		const list = await c.collect(instruments);
		const where = (name: string) => `metrics.instruments:${name}`;
		const unsound = list.flatMap((i) =>
			problemsOf(i).map((reason) => ({ where: where(i.spec.name), reason })),
		);
		if (unsound.length > 0) c.refuseAll(unsound);
		const registry = list.map((instrument) => ({
			instrument,
			...(instrument.kind === "gauge"
				? sampledGauge(instrument, c.log, boundMs)
				: kept(instrument, c.log)),
		}));
		// Attaching starts the counting; an instrument that will not attach is refused below.
		const attached = registry.map(({ instrument, record }) => ({
			instrument,
			ok: attach(instrument, record),
		}));
		const unattached = attached.filter(({ ok }) => !ok);
		if (unattached.length > 0) {
			c.refuseAll(
				unattached.map(({ instrument }) => ({
					where: where(instrument.spec.name),
					reason: "not made by counter, histogram or gauge, or made for another assembly",
				})),
			);
		}
		return Object.freeze({
			read: () => Object.freeze(registry.map(({ read }) => read())),
			sample: async () => Object.freeze(await Promise.all(registry.map(({ sample }) => sample()))),
		});
	};
