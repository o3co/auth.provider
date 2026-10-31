import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { expectedOf } from "../expected.ts";

const entry = (fields: Record<string, unknown> = {}) => ({
	"test-name": "oidcc-ensure-redirect-uri-in-authorization-request",
	variant: { server_metadata: "discovery" },
	"configuration-filename": "op.json",
	"current-block": "Verify authorization endpoint response",
	condition: "CheckForAuthorizationEndpointErrorInQueryParameters",
	"expected-result": "failure",
	class: "adaptation",
	adaptation: "pkce",
	...fields,
});

describe("a plan's expected entries, read from its files", () => {
	it("reads its failures and skips, each taken as the checklist judges it", async () => {
		const dir = await mkdtemp(join(tmpdir(), "expected-"));
		await writeFile(join(dir, "basic.failures.json"), JSON.stringify([entry()]));
		await writeFile(join(dir, "basic.skips.json"), "[]");
		const read = await expectedOf(dir, "basic");
		expect(read.failures).toEqual([entry()]);
		expect(read.skips).toEqual([]);
	});

	it("refuses the plan where a test's failure and its skip name two classes", async () => {
		const dir = await mkdtemp(join(tmpdir(), "expected-"));
		await writeFile(join(dir, "basic.failures.json"), JSON.stringify([entry()]));
		const skip = entry({
			"current-block": undefined,
			condition: undefined,
			"expected-result": undefined,
			class: "third-party",
			adaptation: undefined,
			issue: "https://x",
		});
		await writeFile(join(dir, "basic.skips.json"), JSON.stringify([skip]));
		await expect(expectedOf(dir, "basic")).rejects.toThrow(
			/oidcc-ensure-redirect-uri-in-authorization-request \(op\.json\): a test's entries share one class, here adaptation and third-party/,
		);
	});

	it("refuses the plan, naming each entry that may not be taken", async () => {
		const dir = await mkdtemp(join(tmpdir(), "expected-"));
		await writeFile(
			join(dir, "basic.failures.json"),
			JSON.stringify([entry({ "test-name": "oidcc-*" })]),
		);
		await writeFile(join(dir, "basic.skips.json"), "[]");
		await expect(expectedOf(dir, "basic")).rejects.toThrow(
			/the expected entries of basic may not be taken:\n.*test-name/,
		);
	});
});
