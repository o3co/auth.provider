import { onLegacy } from "@mod/conformance-legacy";
import { deviceArea } from "./area.ts";

onLegacy(deviceArea, {
	// The standalone build does not load the device grant; the composed entry adds it.
	map: (part) => ({
		settings: [
			"device-grant {",
			"enabled = true",
			`verificationUri = ${JSON.stringify(part.verificationUri)}`,
			...(part.attempts ? [`rateLimit { limit = ${part.attempts} }`] : []),
			"}",
			"",
		].join("\n"),
		extra: ["device-grant"],
	}),
});
