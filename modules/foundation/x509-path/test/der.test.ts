import * as asn1js from "asn1js";
import { expect, it } from "vitest";
import { decoded, nodesIn } from "../src/der.ts";

it("reads past asn1js's cap of nodes only where told to, as a CRL is read, by as many as the bytes could hold", () => {
	// 12,000 NULLs in one SEQUENCE: past asn1js's own 10,000 nodes.
	const many = new asn1js.Sequence({
		value: Array.from({ length: 12_000 }, () => new asn1js.Null()),
	});
	const der = new Uint8Array(many.toBER(false));
	const read = (cap?: number) => decoded(der, (schema) => schema, cap);
	expect(read()).toBeUndefined();
	expect(read(nodesIn(der))).toBeDefined();
	expect(read(11_000)).toBeUndefined();
});
