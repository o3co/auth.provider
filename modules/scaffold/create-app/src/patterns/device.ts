import type { Pattern } from "./pattern.ts";
import { simpleWeb } from "./simple-web.ts";

export const device: Pattern = {
	name: "device",
	use:
		"Simple-web with the device authorization grant, for devices without a browser or a keyboard: " +
		"the user reads a code on the device and approves it after logging in on another screen. " +
		"It needs no outside system.",
	axes: simpleWeb.axes,
	features: {
		...simpleWeb.features,
		grants: [...(simpleWeb.features.grants ?? []), "@mod/device-grant"],
	},
	areas: ["keys", "identity", "code", "oauth", "device", "ops"],
	// The token endpoint's own checks (client authentication, introspection, CORS, DPoP) take its tokens.
	conformanceAdd: ["@mod/client-credentials"],
};
