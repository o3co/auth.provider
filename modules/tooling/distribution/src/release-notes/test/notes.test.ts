import { describe, expect, it } from "vitest";
import { notesOf } from "../notes.ts";

const repository = "https://github.com/o3co/auth.provider";

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
		expect(notesOf(changelog, "1.2.0", repository)).toEqual({
			notes: "### Added\n\n- `tokens`: a thing.\n",
		});
	});

	it("take a prerelease's own section, never the final version's", () => {
		expect(notesOf(changelog, "1.2.0-rc.1", repository)).toEqual({
			notes: "### Fixed\n\n- `http`: another.\n",
		});
	});

	it("take the last section up to the end of the file", () => {
		expect(notesOf(changelog, "1.1.0", repository)).toEqual({ notes: "- Older.\n" });
	});

	it("refuse a version with no section, one not dated, and one with nothing in it", () => {
		expect(notesOf(changelog, "1.3.0", repository)).toEqual({
			problem: "CHANGELOG.md has no section for 1.3.0",
		});
		expect(notesOf("## [1.3.0] - Unreleased\n\n- New.\n", "1.3.0", repository)).toEqual({
			problem: "CHANGELOG.md's section for 1.3.0 is not dated",
		});
		expect(
			notesOf("## [1.3.0] - 2026-11-09\n\n## [1.2.0] - 2026-11-02\n", "1.3.0", repository),
		).toEqual({
			problem: "CHANGELOG.md's section for 1.3.0 is empty",
		});
	});

	it("refuse notes for a workspace stating no repository, to point their links at", () => {
		expect(notesOf(changelog, "1.2.0", undefined)).toEqual({
			problem: "package.json states no repository",
		});
	});

	it("refuse notes for a repository that is not a plain https URL, naming the form to state", () => {
		for (const stated of [
			"git+https://github.com/o3co/auth.provider.git",
			"https://github.com/o3co/auth.provider.git",
			"git@github.com:o3co/auth.provider",
			"ssh://git@github.com/o3co/auth.provider",
		]) {
			expect(notesOf(changelog, "1.2.0", stated), stated).toEqual({
				problem: `package.json's repository is ${stated}; state it as a plain https URL, without git+ or .git`,
			});
		}
	});

	it("refuse a version with two sections", () => {
		expect(
			notesOf(`${changelog}\n## [1.1.0] - 2026-09-01\n\n- Again.\n`, "1.1.0", repository),
		).toEqual({
			problem: "CHANGELOG.md has 2 sections for 1.1.0",
		});
	});

	it("point a link relative to the repository at the file in the version's tag, as a release page has no repository to resolve it in", () => {
		const section = [
			"## [1.2.0] - 2026-11-02",
			"",
			"- `tokens`: see [U-1](docs/migration.md#u-1.2-1) and [the policy](SECURITY.md).",
			"- Unchanged: [the format](https://keepachangelog.com/en/1.1.0/) and [above](#added).",
		].join("\n");
		expect(notesOf(section, "1.2.0", repository)).toEqual({
			notes: [
				"- `tokens`: see [U-1](https://github.com/o3co/auth.provider/blob/v1.2.0/docs/migration.md#u-1.2-1) and [the policy](https://github.com/o3co/auth.provider/blob/v1.2.0/SECURITY.md).",
				"- Unchanged: [the format](https://keepachangelog.com/en/1.1.0/) and [above](#added).",
				"",
			].join("\n"),
		});
	});
});
