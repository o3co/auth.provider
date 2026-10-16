import { area } from "@mod/conformance";

/** The operations routes: liveness, readiness and the metrics scrape. */
export interface OpsPart {
	/** Where the scrape answers, where a scene is about refusing a wrong one. */
	readonly scrapePath?: string;
	/** The level the process logs at, where a scene is about refusing one it does not know. */
	readonly logLevel?: string;
}

export const opsArea = area<OpsPart>("ops");

/** The need to set where the scrape answers. */
export const scrapePathSetting = "ops:scrape-path";
