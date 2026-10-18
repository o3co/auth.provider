import { parseWithSchema } from "@o3co/ts.hocon/zod";
import { expect, it } from "vitest";
import { z } from "zod";
import { setting } from "../setting.ts";

const section = z.strictObject({
	ttl: setting.duration("s").pipe(z.number().int().min(1)),
	body: setting.size("KiB").optional(),
	wait: setting.duration("ms").prefault("2s"),
});

it("reads a duration and a size that name their unit, in the unit the key asks for", () => {
	expect(parseWithSchema('ttl = 2m, body = "1 MiB"', section)).toEqual({
		ttl: 120,
		body: 1024,
		wait: 2000,
	});
	expect(section.parse({ ttl: "30s", body: "64KiB" })).toEqual({ ttl: 30, body: 64, wait: 2000 });
});

it("refuses a duration or a size that names no unit, as written or as an environment variable gives it", () => {
	for (const ttl of [30, "30"]) expect(section.safeParse({ ttl }).success, String(ttl)).toBe(false);
	expect(section.safeParse({ ttl: "30s", body: 1024 }).success).toBe(false);
	expect(() => parseWithSchema("ttl = 30", section)).toThrow();
});

it("leaves bounds to the schema it is piped into", () => {
	expect(section.safeParse({ ttl: "500ms" }).success).toBe(false);
});

it("describes a key by what the operator writes, so a section's schema can be told in JSON Schema", () => {
	const told = section["~standard"].jsonSchema.input({ target: "draft-2020-12" });
	expect(told.properties).toMatchObject({
		ttl: { type: "string" },
		body: { type: "string" },
		wait: { type: "string", default: "2s" },
	});
});
