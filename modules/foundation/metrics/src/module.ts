import { defineModule } from "@mod/kernel";
import { gaugeBoundMs, metricsBy } from "./build.ts";
import { metrics } from "./contract.ts";

export default defineModule({ name: "metrics", replicaSafe: true }, (m) => [
	m.provide(metrics).by(metricsBy(gaugeBoundMs)),
]);
