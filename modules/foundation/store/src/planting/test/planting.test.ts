import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { type Space, spaces, store } from "../../contract.ts";
import { simulatedStore } from "../../simulated/simulated.ts";
import { plantValue } from "../planting.ts";

const subjects: Space = { name: "held", guarantees: ["durable"], subjectData: "online-indexed" };
const plain: Space = { name: "plain", guarantees: [], subjectData: "none" };

it("plants a value at a key, in a space of subjects' data or any other, kept until its expiry", async () => {
	const app = await assemble({
		modules: [
			simulatedStore().module,
			defineModule({ name: "owner", replicaSafe: true, takes: [] }, (m) => [
				m.contribute(spaces).by(() => subjects),
				m.contribute(spaces).by(() => plain),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const s = app.get(store);
	for (const space of [subjects, plain]) {
		const key = { space, partition: "p", name: "record" };
		expect((await plantValue(s, key, { n: 19 }, { kind: "never" })).kind).toBe("committed");
		expect((await plantValue(s, key, { n: 20 }, { kind: "after", ms: 60_000 })).kind).toBe(
			"committed",
		);
		const { entry } = await s.get(key);
		expect(entry?.value).toEqual({ n: 20 });
		expect(entry?.expiresAt).toBeGreaterThan(0);
	}
});
