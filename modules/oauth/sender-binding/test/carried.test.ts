import { expect, it } from "vitest";
import { carried } from "../src/contract.ts";

const bound = (member: string, confirmation: string) => ({ member, confirmation, tokenType: "T" });

it("refuses a held binding the request does not prove, so it cannot be washed off", () => {
	expect(carried([bound("jkt", "k1")], undefined)).toEqual({ kind: "refused" });
	expect(carried([bound("jkt", "k1")], bound("jkt", "k2"))).toEqual({ kind: "refused" });
	expect(carried([bound("jkt", "k1")], bound("x5t#S256", "k1"))).toEqual({ kind: "refused" });
	// An unbound subject does not excuse a bound actor.
	expect(carried([undefined, bound("jkt", "k1")], undefined)).toEqual({ kind: "refused" });
});

it("refuses two different held bindings, whichever one the request proves", () => {
	const subject = bound("jkt", "k1");
	const actor = bound("jkt", "k2");
	expect(carried([subject, actor], subject)).toEqual({ kind: "refused" });
	expect(carried([subject, actor], actor)).toEqual({ kind: "refused" });
});

it("carries the binding the request proves to the new token", () => {
	expect(carried([bound("jkt", "k1"), bound("jkt", "k1")], bound("jkt", "k1"))).toEqual({
		kind: "carry",
		binding: bound("jkt", "k1"),
	});
	// A proof from the actor binds the new token even when no presented token is bound.
	expect(carried([undefined, undefined], bound("jkt", "k3"))).toEqual({
		kind: "carry",
		binding: bound("jkt", "k3"),
	});
});

it("carries no binding when nothing is bound and nothing is proved", () => {
	expect(carried([undefined], undefined)).toEqual({ kind: "carry" });
	expect(carried([], undefined)).toEqual({ kind: "carry" });
});
