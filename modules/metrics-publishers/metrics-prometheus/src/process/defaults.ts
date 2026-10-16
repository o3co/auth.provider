import { collectDefaultMetrics, Registry } from "prom-client";

const PREFIX = "auth_provider_";

/** The process's own counts exist once per process, so their registry is made once. */
let made: Registry | undefined;

/** The first call, from either function below, starts counting. */
function registry(): Registry {
	if (!made) {
		made = new Registry();
		collectDefaultMetrics({ register: made, prefix: PREFIX });
	}
	return made;
}

/** The names the process's counts take in the text, with a histogram's derived ones. */
export function processNames(): string[] {
	return registry()
		.getMetricsAsArray()
		.flatMap(({ name, type }) =>
			// prom-client types this as a numeric enum, but the value is the string "histogram".
			String(type) === "histogram"
				? [name, `${name}_bucket`, `${name}_sum`, `${name}_count`]
				: [name],
		);
}

/** The process's counts in the text format, read now. */
export function processText(): Promise<string> {
	return registry().metrics();
}
