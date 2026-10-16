import { expect, it } from "vitest";
import { type AuditRecord, auditEvents, declaredAudit } from "../src/contract.ts";

const events = auditEvents({
	"thing.made": { attributes: ["client"], when: "a thing is made" },
	"thing.lost": { attributes: [], when: "a thing is lost" },
});

it("records a declared kind with its declared attributes, as the audit takes it", () => {
	const taken: AuditRecord[] = [];
	// It takes only what it calls, so a stand-in need not answer losses.
	const recorder = declaredAudit({ record: (e) => taken.push(e) }, events);
	recorder.record("thing.made", { subject: "ann", attributes: { client: "tv" } });
	recorder.record("thing.lost");
	expect(taken).toEqual([
		{ kind: "thing.made", subject: "ann", attributes: { client: "tv" } },
		{ kind: "thing.lost" },
	]);
	// The types refuse an undeclared kind or attribute; at run time either throws, so none slips past a cast.
	expect(() => recorder.record("thing.other" as never)).toThrow("thing.other is not declared");
	expect(() =>
		recorder.record("thing.made", { attributes: { client: "tv", secret: "x" } as never }),
	).toThrow("thing.made does not declare secret");
});

it("keeps the declarations as written, for the audit event reference", () => {
	expect(events["thing.made"]).toEqual({ attributes: ["client"], when: "a thing is made" });
	expect(Object.isFrozen(events)).toBe(true);
});
