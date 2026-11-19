import { erasureCommands } from "@mod/account-erasure";
import accountErasure from "@mod/account-erasure/module";
import journalFile from "@mod/erasure-journal-file/module";
import { erasureJournalFileConfig } from "@mod/erasure-journal-file/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { storeControl } from "@mod/store";
import storeModule from "@mod/store/module";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

it("boots account erasure over the store through this wiring, and erasure-enter enters, shown alone", async () => {
	const app = await assemble({
		modules: [storeModule, journalFile, wiring, accountErasure],
		config: {
			...kernelConfig(),
			store: { "accept-volatile": true },
			...erasureJournalFileConfig(),
		},
		runtime: quietRuntime(),
	});
	const run = await (await app.get(erasureCommands)).enter([]);
	const record = await (await app.get(storeControl)).control();
	expect(run).toEqual({
		lines: [`entered maintenance under epoch ${record.epoch}; this process was shown alone`],
		code: 0,
	});
	expect(record.maintenance).toBe(true);
	expect(record.marks["account-erasure.entered"]?.epoch).toBe(record.epoch);
});
