import { onNew } from "@mod/conformance";
import { deviceArea } from "./area.ts";

onNew(deviceArea, (part) => ({
	modules: ["@mod/device-grant"],
	store: "volatile",
	config: {
		"device-grant": {
			"verification-uri": part.verificationUri,
			...(part.attempts ? { attempts: part.attempts } : {}),
		},
	},
}));
