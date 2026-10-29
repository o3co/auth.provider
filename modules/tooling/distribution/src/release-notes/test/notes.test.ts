import { describe, expect, it } from "vitest";
import { notesOf } from "../notes.ts";

const changelog = [
	"# Changelog",
	"",
	"Notable changes, newest first.",
	"",
	"## [1.2.0] - 2026-11-02",
	"",
	"### Added",
	"",
	"- `tokens`: a thing.",
	"",
	"## [1.2.0-rc.1] - 2026-10-30",
	"",
	"### Fixed",
	"",
	"- `http`: another.",
	"",
	"## [1.1.0] - 2026-10-01",
	"",
	"- Older.",
	"",
].join("\n");

describe("the release's notes, from the version's section of the changelog", () => {
	it("are the section's body, from its heading to the next version's", () => {
		expect(notesOf(changelog, "1.2.0")).toEqual({
			notes: "### Added\n\n- `tokens`: a thing.\n",
		});
	});

	it("take a prerelease's own section, never the final version's", () => {
		expect(notesOf(changelog, "1.2.0-rc.1")).toEqual({
			notes: "### Fixed\n\n- `http`: another.\n",
		});
	});

	it("take the last section up to the end of the file", () => {
		expect(notesOf(changelog, "1.1.0")).toEqual({ notes: "- Older.\n" });
	});

	it("refuse a version with no section, one not dated, and one with nothing in it", () => {
		expect(notesOf(changelog, "1.3.0")).toEqual({
			problem: "CHANGELOG.md has no section for 1.3.0",
		});
		expect(notesOf("## [1.3.0] - Unreleased\n\n- New.\n", "1.3.0")).toEqual({
			problem: "CHANGELOG.md's section for 1.3.0 is not dated",
		});
		expect(notesOf("## [1.3.0] - 2026-11-09\n\n## [1.2.0] - 2026-11-02\n", "1.3.0")).toEqual({
			problem: "CHANGELOG.md's section for 1.3.0 is empty",
		});
	});

	it("refuse a version with two sections", () => {
		expect(notesOf(`${changelog}\n## [1.1.0] - 2026-09-01\n\n- Again.\n`, "1.1.0")).toEqual({
			problem: "CHANGELOG.md has 2 sections for 1.1.0",
		});
	});
});
