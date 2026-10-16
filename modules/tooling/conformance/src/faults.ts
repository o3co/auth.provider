import { afterAll, beforeAll } from "vitest";
import { type AreaScene, areaTarget } from "./areas.ts";
import type { Started } from "./driver.ts";

/** A second run of the scene whose store can be made unreachable; call it inside a describe. */
export function faultyTarget(scene: AreaScene) {
	let started: Started | undefined;
	beforeAll(async () => {
		started = await areaTarget().start({ ...scene, storeFaults: true });
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	const running = () => {
		if (started?.kind !== "running") throw new Error("the faulty target is not running");
		return started;
	};
	return {
		base: () => running().baseUrl,
		mail: () => running().mail,
		/** Runs `during` while the store is unreachable, and brings it back whatever happens. */
		async whileDown<T>(during: () => Promise<T>): Promise<T> {
			await running().fault?.(true);
			try {
				return await during();
			} finally {
				await running().fault?.(false);
			}
		},
	};
}
