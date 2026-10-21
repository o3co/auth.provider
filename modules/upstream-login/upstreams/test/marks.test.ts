import { expect, it } from "vitest";
import { UpstreamMismatch, UpstreamRefused } from "../src/contract.ts";

/** An error as another copy of upstreams in the same bundle would make it: another class, the same mark. */
const fromAnotherCopy = (name: string, mark: string) =>
	Object.assign(new Error(name), { [Symbol.for(mark)]: true });

it("tells a refusal and a mismatch by their marks, whatever copy of upstreams made them", () => {
	expect(UpstreamRefused.is(new UpstreamRefused())).toBe(true);
	expect(UpstreamRefused.is(fromAnotherCopy("refused", "@mod/upstreams.refused"))).toBe(true);
	expect(UpstreamMismatch.is(new UpstreamMismatch("no issuer", ["issuer"]))).toBe(true);
	expect(UpstreamMismatch.is(fromAnotherCopy("mismatch", "@mod/upstreams.mismatch"))).toBe(true);
});

it("tells neither from another error, nor one from the other", () => {
	for (const other of [new Error("upstream refused"), "upstream refused", undefined, null]) {
		expect(UpstreamRefused.is(other)).toBe(false);
		expect(UpstreamMismatch.is(other)).toBe(false);
	}
	expect(UpstreamRefused.is(new UpstreamMismatch("x"))).toBe(false);
	expect(UpstreamMismatch.is(new UpstreamRefused())).toBe(false);
});
