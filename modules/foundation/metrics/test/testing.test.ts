import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { gaugeBoundMs } from "../src/build.ts";
import { type Instrument, instruments, metrics } from "../src/contract.ts";
import metricsModule from "../src/module.ts";
import { metricsContract, metricsStandIn } from "../src/testing.ts";

/** Opens metrics composed as given, with the instruments an emitter makes at its build. */
const opening =
	(composed: Module, boundMs: number) => async (made: () => readonly Instrument[]) => {
		const recorded = recordingLog();
		const emitter = defineModule({ name: "emitter", takes: [] }, (m) =>
			made().map((i) => m.contribute(instruments).by(() => i)),
		);
		const app = await assemble({
			modules: [composed, emitter],
			config: kernelConfig(),
			runtime: quietRuntime({ log: recorded.log }),
		});
		return {
			metrics: app.get(metrics),
			warned: () =>
				recorded
					.lines()
					.filter((line) => line.level === "warn")
					.map((line) => [line.event, line.fields] as const),
			boundMs,
		};
	};

metricsContract("the module", opening(metricsModule, gaugeBoundMs));
metricsContract("the stand-in", opening(metricsStandIn(20), 20));
