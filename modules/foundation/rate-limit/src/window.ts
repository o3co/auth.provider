import { type Window, windowCeilingMs } from "./contract.ts";

/** Refuses a window longer than the ceiling with a TypeError, before anything is counted. */
export function withinCeiling(window: Window): void {
	if (window.ms > windowCeilingMs) {
		throw new TypeError(
			`rate-limit: a window lasts at most ${windowCeilingMs} ms (windowCeilingMs); ${window.ms} ms asked`,
		);
	}
}
