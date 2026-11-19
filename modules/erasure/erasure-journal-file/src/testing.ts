import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** The erasure-journal-file part of a test's configuration: a fresh journal path of the test's own, unless the test sets one. */
export function erasureJournalFileConfig(settings: { readonly path?: string } = {}) {
	return {
		"erasure-journal-file": {
			// A directory is made only where the test sets no path, so none is left unused.
			path: settings.path ?? join(mkdtempSync(join(tmpdir(), "erasure-journal-")), "journal"),
		},
	};
}
