import { onLegacy } from "@mod/conformance-legacy";
import { opsArea, scrapePathSetting } from "./area.ts";

// The standalone build always answers the three routes, at fixed paths.
onLegacy(opsArea, {
	// Its log level sits in a logging block of its configuration file.
	map: (part) =>
		part.logLevel === undefined
			? {}
			: { settings: `logging { level = ${JSON.stringify(part.logLevel)} }\n` },
	// The legacy build has no setting for where the scrape answers.
	cannot: [scrapePathSetting],
});
