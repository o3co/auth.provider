import { describe, expect, it } from "vitest";
import { archiveProblems, entriesOf } from "../archive.ts";
import { unicodePath, zipOf } from "./zip.ts";

describe("entriesOf", () => {
	it("takes as files and directories only what MS-DOS and Unix mark so, as CI's archives hold them", () => {
		const zip = zipOf([
			{ name: "a/report.json", data: "{}" },
			{ name: "a/", data: "", mode: 0o040755 },
			{ name: "dos.json", data: "{}", host: 0, mode: 0 },
			{ name: "dos/", data: "", host: 0, mode: 0 },
		]);
		expect(entriesOf(zip)).toEqual({
			entries: [
				{ name: "a/report.json", kind: "file" },
				{ name: "a/", kind: "directory" },
				{ name: "dos.json", kind: "file" },
				{ name: "dos/", kind: "directory" },
			],
		});
	});

	it("takes as other a link, a device or any mode it does not know, and every other host", () => {
		const others = zipOf([
			{ name: "link", data: "/etc/passwd", mode: 0o120777 },
			{ name: "fifo", data: "", mode: 0o010644 },
			{ name: "bare", data: "{}", mode: 0 },
			{ name: "beos", data: "/etc", mode: 0o120777, host: 16 },
			{ name: "atheos", data: "/etc", mode: 0o120777, host: 30 },
			{ name: "mac", data: "{}", mode: 0o100644, host: 19 },
		]);
		const read = entriesOf(others);
		expect("entries" in read && read.entries.map((e) => e.kind)).toEqual(Array(6).fill("other"));
	});

	it("tells an entry its local header or an extra field names otherwise than the directory", () => {
		const zip = zipOf([
			{ name: "fine.json", data: "{}" },
			{ name: "local.json", data: "{}", localName: "../escaped.json" },
			{
				name: "central.json",
				data: "{}",
				centralExtra: unicodePath("central.json", "../escaped.json"),
			},
			{ name: "inner.json", data: "{}", localExtra: unicodePath("inner.json", "../escaped.json") },
		]);
		expect(entriesOf(zip)).toEqual({
			entries: [
				{ name: "fine.json", kind: "file" },
				{ name: "local.json", kind: "file", renamed: true },
				{ name: "central.json", kind: "file", renamed: true },
				{ name: "inner.json", kind: "file", renamed: true },
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
				{ name: "a/b.json", kind: "file" },
				{ name: "c.json", kind: "file" },
			]),
		).toEqual([]);
	});

	it("refuses a link, and a name that would land outside the directory", () => {
		expect(
			archiveProblems([
				{ name: "out", kind: "other" },
				{ name: "report.json", kind: "file", renamed: true },
				{ name: "../escape.json", kind: "file" },
				{ name: "a/../../escape.json", kind: "file" },
				{ name: "/etc/passwd", kind: "file" },
				{ name: "C:/x.json", kind: "file" },
				{ name: "a\\..\\b.json", kind: "file" },
				{ name: "", kind: "file" },
			]),
		).toEqual([
			"out is neither a file nor a directory as this check takes them",
			"report.json is named otherwise by its local header or an extra field",
			'"../escape.json" would land outside the directory',
			'"a/../../escape.json" would land outside the directory',
			'"/etc/passwd" would land outside the directory',
			'"C:/x.json" would land outside the directory',
			'"a\\\\..\\\\b.json" would land outside the directory',
			'"" would land outside the directory',
		]);
	});
});
