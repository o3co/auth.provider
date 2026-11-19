import { erasureJournal } from "@mod/erasure-journal";
import { defineModule } from "@mod/kernel";
import { enterCommand, erasureCommands } from "./commands/commands.ts";
import { erasureMaintenance } from "./maintenance/maintenance.ts";

// Holds nothing of its own, so it is safe on many instances.
export default defineModule(
	{
		name: "account-erasure",
		replicaSafe: true,
		takes: [erasureMaintenance, erasureJournal],
	},
	(m) => [
		m.provide(erasureCommands).by(async (c) => {
			const parts = {
				journal: await c.get(erasureJournal),
				maintenance: await c.get(erasureMaintenance),
				clock: c.clock,
			};
			return { enter: enterCommand(parts) };
		}),
	],
);
