import { onNew } from "@mod/conformance";
import { type OpsPart, opsArea } from "./area.ts";

onNew(opsArea, (part: OpsPart) => ({
	modules: ["@mod/metrics", "@mod/metrics-prometheus"],
	config: {
		...(part.scrapePath === undefined ? {} : { "metrics-prometheus": { path: part.scrapePath } }),
		...(part.logLevel === undefined ? {} : { kernel: { logging: { level: part.logLevel } } }),
	},
}));
