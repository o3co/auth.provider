import { expect, it } from "vitest";
import { nodeChecked } from "../node.ts";

const index = (releases: readonly { version: string; security: boolean }[]) => async () =>
	JSON.stringify(releases.map((r) => ({ ...r, date: "2026-11-01", files: [] })));

it("passes a Node no security release of its major is newer than", async () => {
	const checked = await nodeChecked(
		"v24.22.3",
		index([
			{ version: "v26.1.0", security: true },
			{ version: "v24.22.3", security: true },
			{ version: "v24.22.2", security: false },
		]),
	);
	expect(checked).toEqual({ behind: false, version: "v24.22.3" });
});

it("fails a Node behind a security release of its major, naming the newest and its minor", async () => {
	const checked = await nodeChecked(
		"v24.22.3\n",
		index([
			{ version: "v24.24.0", security: false },
			{ version: "v24.23.1", security: true },
			{ version: "v24.22.4", security: true },
			{ version: "v24.22.3", security: false },
		]),
	);
	expect(checked).toEqual({
		behind: true,
		version: "v24.22.3",
		newest: "v24.23.1",
		minor: "24.23",
	});
});

it("tells a malformed index, or one not listing the image's Node, as not checked", async () => {
	for (const malformed of [
		async () => "not json",
		async () => '{"version":"v24.22.3"}',
		async () => '[{"version":24}]',
		index([{ version: "v24.22.4", security: true }]),
	])
		expect(await nodeChecked("v24.22.3", malformed)).toHaveProperty("notChecked");
	expect(await nodeChecked("24", index([]))).toEqual({
		notChecked: "the image's Node version is not one: 24",
	});
});

it("tells an index that could not be fetched as not checked, never as passed", async () => {
	const checked = await nodeChecked("v24.22.3", async () => {
		throw new Error("fetch failed: ENOTFOUND nodejs.org");
	});
	expect(checked).toEqual({
		notChecked: "Node's release index could not be read: fetch failed: ENOTFOUND nodejs.org",
	});
});
