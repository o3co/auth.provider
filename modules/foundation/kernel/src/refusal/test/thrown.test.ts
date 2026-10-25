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

	it("names only what the kernel knows: any other error's name is Error, never told", () => {
		const named = (name: unknown) => Object.assign(new Error("x"), { name });
		expect(thrownKind(named("PRIVATE_NAME"))).toBe("Error");
		expect(thrownKind(named("token=abc"))).toBe("Error");
		expect(thrownKind(named(42))).toBe("Error");
		expect(thrownKind(named("AbortError"))).toBe("AbortError");
		expect(thrownKind({ name: "TypeError" })).toBe("object");
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
