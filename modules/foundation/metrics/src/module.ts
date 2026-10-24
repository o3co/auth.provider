import { defineModule } from "@mod/kernel";
import { gaugeBoundMs, metricsBy, metricsTakes } from "./build.ts";
import { metrics } from "./contract.ts";

export default defineModule({ name: "metrics", replicaSafe: true, takes: metricsTakes }, (m) => [
	m.provide(metrics).by(metricsBy(gaugeBoundMs)),
]);
