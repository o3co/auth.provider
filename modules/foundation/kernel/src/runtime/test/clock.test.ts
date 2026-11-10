import { expect, it } from "vitest";
import { quietRuntime } from "../../testing.ts";
import { systemClock } from "../runtime.ts";

it("gives the system's epoch ms, and a monotonic time that never goes back and only measures differences", async () => {
	const monotonic = systemClock.monotonic;
	if (!monotonic) throw new Error("the system clock gives a monotonic time");
	const first = monotonic();
	await new Promise((later) => setTimeout(later, 20));
	const second = monotonic();
	expect(second).toBeGreaterThanOrEqual(first + 15);
	const now = systemClock.now();
	expect(Math.abs(now - Date.now())).toBeLessThan(1000);
	// A test's runtime gives the same, unless the test sets its own clock.
	expect(quietRuntime().clock.monotonic).toBe(monotonic);
});
