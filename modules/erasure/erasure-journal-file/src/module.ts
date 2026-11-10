import { erasureJournal } from "@mod/erasure-journal";
import { defineModule } from "@mod/kernel";
import { z } from "zod";
import { nodeFiles } from "./files.ts";
import { journalFileWith } from "./journal.ts";

const section = z.strictObject({
	path: z
		.string()
		.min(1)
		.refine((path) => path.startsWith("/"), "an absolute path")
		.describe(
			"The journal's file, an absolute path on the one node that runs erasure, kept apart from the store's backups. Its lock is the same path with `.lock` added.",
		),
});

// Not safe on many instances: the journal is one file on the one node that runs erasure.
export default defineModule(
	{ name: "erasure-journal-file", section, replicaSafe: false, takes: [] },
	(m) => [
		m.provide(erasureJournal).by((c) =>
			journalFileWith({
				path: c.section.path,
				files: nodeFiles,
				clock: c.clock,
				random: c.random,
			}),
		),
	],
);
