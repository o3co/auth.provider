import { noStore, routes } from "@mod/http";
import { contract, defineModule } from "@mod/kernel";
import { metrics } from "@mod/metrics";
import { processNames, processText } from "./process/defaults.ts";
import { section } from "./section.ts";
import { contentType, textOf, unwritable } from "./text/text.ts";

/** The scrape's body: metrics' series, then the process's own counts. */
const scrape = contract<{ body(): Promise<string> }>("metrics-prometheus.scrape");

export default defineModule({ name: "metrics-prometheus", section, replicaSafe: true }, (m) => [
	m.provide(scrape).by(async (c) => {
		const counts = await c.get(metrics);
		const problems = unwritable(counts.read(), processNames());
		if (problems.length > 0) {
			c.refuseAll(
				problems.map(({ name, reason }) => ({ where: `metrics-prometheus:${name}`, reason })),
			);
		}
		return { body: async () => textOf(await counts.sample()) + (await processText()) };
	}),
	// The handler reads the scrape late: building it here would wait on http's routes, this one among them.
	m.contribute(routes).by((c) => {
		const scraped = c.late(scrape);
		return {
			method: "GET",
			changesState: false,
			path: c.section.path,
			takes: ["none"],
			handle: async () => ({
				status: 200,
				headers: { ...noStore, "content-type": contentType },
				body: await scraped().body(),
			}),
		};
	}),
]);
