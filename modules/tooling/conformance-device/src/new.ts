import { type NewPart, onNew } from "@mod/conformance";
import { type DevicePart, deviceArea } from "./area.ts";

/** The device grant, with session-tokens, which records its tokens to the session that approved them, as device-grant asks to boot. */
export const setUp = (part: DevicePart): NewPart => ({
	modules: ["@mod/device-grant", "@mod/session-tokens"],
	store: "volatile",
	config: {
		"device-grant": {
			"verification-uri": part.verificationUri,
			...(part.attempts ? { attempts: part.attempts } : {}),
		},
	},
});

onNew(deviceArea, setUp);
