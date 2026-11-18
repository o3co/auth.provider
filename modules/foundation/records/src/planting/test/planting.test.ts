import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import { recordsIn, secretRecordsIn } from "../../records.ts";
import { changeRecords } from "../../together/together.ts";
import { plantRecord } from "../planting.ts";

const plain: Space = { name: "plain", guarantees: [], subjectData: "none" };
const secrets: Space = { name: "secrets", guarantees: [], subjectData: "none" };
const subjects: Space = { name: "subjects", guarantees: [], subjectData: "online-indexed" };
const held = contract<Store>("test.planting-store");
const random = { bytes: (n: number) => new Uint8Array(n).fill(3) };

async function opened() {
	const app = await assemble({
		modules: [
			simulatedStore().module,
			defineModule({ name: "owner", replicaSafe: false, takes: [store] }, (m) => [
				...[plain, secrets, subjects].map((space) => m.contribute(spaces).by(() => space)),
				m.provide(held).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	return app.get(held);
}

it("plants a record that records read as one they wrote, by key or under a secret", async () => {
	const s = await opened();
	const place = (space: Space) => ({ store: s, space, random });
	await plantRecord({ place: place(plain), key: "k" }, { n: 19 });
	expect(await recordsIn(place(plain)).read("k")).toEqual({ n: 19 });
	await plantRecord({ place: place(secrets), secret: "the-code" }, { n: 20 }, 60_000);
	expect(await secretRecordsIn(place(secrets)).read("the-code")).toEqual({ n: 20 });
});

it("plants in a space of subjects' data, ending after its lifetime or never", async () => {
	const s = await opened();
	const place = { store: s, space: subjects, random };
	await plantRecord({ place, key: "endless" }, { n: 1 });
	await plantRecord({ place, key: "ending" }, { n: 2 }, 60_000);
	const endless = await s.get(changeRecords.keyOf({ place, key: "endless" }));
	const ending = await s.get(changeRecords.keyOf({ place, key: "ending" }));
	expect([endless.entry?.value, endless.entry?.expiresAt]).toEqual([{ n: 1 }, null]);
	expect(ending.entry?.value).toEqual({ n: 2 });
	expect(ending.entry?.expiresAt).toEqual(expect.any(Number));
});
