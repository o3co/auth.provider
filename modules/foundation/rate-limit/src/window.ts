import { type Window, windowCeilingMs } from "./contract.ts";

/**
 * Refuses a window not within the ceiling with a TypeError, before anything is counted: one longer,
 * or a length that is no number (NaN compares false with anything, so the test is written to fail it).
 */
export function withinCeiling(window: Window): void {
	if (!(window.ms <= windowCeilingMs)) {
		throw new TypeError(
			`rate-limit: a window lasts at most ${windowCeilingMs} ms (windowCeilingMs); one of ${window.ms} ms asked`,
		);
	}
}
