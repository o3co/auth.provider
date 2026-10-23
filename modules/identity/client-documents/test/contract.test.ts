import type { Section } from "@mod/clients";
import { describe, expect, it } from "vitest";
import { documentCopies } from "../src/contract.ts";

describe("client-documents", () => {
	it("offers the copies keyed by the name of the section each fills", () => {
		const section = { name: "consent" } as Section<unknown>;
		const copy = { section, reads: ["client_name"], copy: () => undefined };
		expect([documentCopies.label, documentCopies.rule.multiplicity]).toEqual([
			"client-documents.copies",
			"keyed",
		]);
		expect(
			documentCopies.rule.multiplicity === "keyed" ? documentCopies.rule.keyOf(copy) : undefined,
		).toBe("consent");
	});
});
