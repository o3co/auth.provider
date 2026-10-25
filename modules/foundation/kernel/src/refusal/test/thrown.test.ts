import { describe, expect, it } from "vitest";
import { unreadable } from "../../../test/refusals.ts";
import { readThrown, thrownKind } from "../refusal.ts";

describe("reading a thrown value", () => {
	it("answers what the read makes of it", () => {
		expect(readThrown(() => 7, 0)).toBe(7);
	});

	it("answers the fallback where the read throws, never throwing", () => {
		expect(readThrown(() => (unreadable()[0] as { x?: number }).x ?? 1, 0)).toBe(0);
		expect(
			readThrown(() => {
				throw new Error("no");
			}, "fallback"),
		).toBe("fallback");
	});
});

describe("a thrown value's kind", () => {
	it("is an error's name, or the value's type", () => {
		expect(thrownKind(new TypeError("x"))).toBe("TypeError");
		expect(thrownKind("text")).toBe("string");
		expect(thrownKind(undefined)).toBe("undefined");
	});

	it("is unknown where reading it throws: a revoked proxy, a name getter that throws", () => {
		const nameless = Object.defineProperty(new Error("x"), "name", {
			get() {
				throw new Error("no name");
			},
		});
		expect(thrownKind(unreadable()[0])).toBe("unknown");
		expect(thrownKind(nameless)).toBe("unknown");
	});
});
