import { describe, expect, it } from "vitest";
import { type Started, untilPortHeld } from "../src/driver.ts";

const running: Started = { kind: "running", baseUrl: "http://127.0.0.1:1", stop: async () => {} };
const taken: Started = {
	kind: "refused",
	output: "Error: listen EADDRINUSE: address already in use",
};
const refused: Started = { kind: "refused", output: "refused http.port: Invalid input" };

/** A launcher answering in turn as given, keeping the ports it was asked to listen on. */
const launcher = (...answers: Started[]) => {
	const ports: number[] = [];
	return {
		ports,
		launch: async (port: number) => {
			ports.push(port);
			return answers[ports.length - 1] ?? running;
		},
	};
};

describe("starting a target at a free port", () => {
	it("tries a new port when another process took the one chosen before the target bound it", async () => {
		const l = launcher(taken, running);
		expect(await untilPortHeld(l.launch, 3)).toBe(running);
		expect(l.ports).toHaveLength(2);
		expect(l.ports[0]).not.toBe(l.ports[1]);
	});

	it("answers any other refusal at once, and the last after as many tries as given", async () => {
		const once = launcher(refused);
		expect(await untilPortHeld(once.launch, 3)).toBe(refused);
		expect(once.ports).toHaveLength(1);
		const always = launcher(taken, taken, taken);
		expect(await untilPortHeld(always.launch, 3)).toBe(taken);
		expect(always.ports).toHaveLength(3);
	});
});
