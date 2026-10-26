import { describe, expect, it } from "vitest";
import { archiveProblems, entriesOf } from "../archive.ts";
import { zipOf } from "./zip.ts";

describe("entriesOf", () => {
	it("reads each entry's name, and whether a Unix or macOS host made it a link", () => {
		const zip = zipOf([
			{ name: "a/report.json", data: "{}" },
			{ name: "out", data: "/etc/passwd", mode: 0o120777 },
			{ name: "mac", data: "/etc", mode: 0o120755, host: 19 },
			{ name: "dos", data: "x", mode: 0o120777, host: 0 },
		]);
		expect(entriesOf(zip)).toEqual({
			entries: [
				{ name: "a/report.json", link: false },
				{ name: "out", link: true },
				{ name: "mac", link: true },
				{ name: "dos", link: false },
			],
		});
	});

	it("reads nothing that is no ZIP archive", () => {
		expect(entriesOf(Buffer.from("not a zip"))).toEqual({ problem: "no ZIP archive" });
	});
});

describe("archiveProblems", () => {
	it("passes entries that land inside the directory", () => {
		expect(
			archiveProblems([
				{ name: "a/b.json", link: false },
				{ name: "c.json", link: false },
			]),
		).toEqual([]);
	});

	it("refuses a link, and a name that would land outside the directory", () => {
		expect(
			archiveProblems([
				{ name: "out", link: true },
				{ name: "../escape.json", link: false },
				{ name: "a/../../escape.json", link: false },
				{ name: "/etc/passwd", link: false },
				{ name: "C:/x.json", link: false },
				{ name: "a\\..\\b.json", link: false },
				{ name: "", link: false },
			]),
		).toEqual([
			"out is a link",
			'"../escape.json" would land outside the directory',
			'"a/../../escape.json" would land outside the directory',
			'"/etc/passwd" would land outside the directory',
			'"C:/x.json" would land outside the directory',
			'"a\\\\..\\\\b.json" would land outside the directory',
			'"" would land outside the directory',
		]);
	});
});
