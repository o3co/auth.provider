import { expect, it } from "vitest";
import { recordingLog } from "../../testing.ts";
import type { LogFields } from "../runtime.ts";

it("refuses, by its type, a log field taking a line's own name, and takes any other fields", () => {
	const { log, lines } = recordingLog();
	// @ts-expect-error a sink writes the line's own at beside the fields, so a field named at is lost
	log.warn("e", { at: "x" });
	const typed: { at: string } = { at: "x" };
	// @ts-expect-error the same, given as a value typed so
	log.warn("e", typed);
	// A value typed by an index signature alone, as LogFields, passes whatever it holds: the type
	// refuses a name it can see, and the sink drops the rest.
	const given: LogFields = { key: "k", n: 1 };
	log.warn("e", { ...given, more: true });
	// A union of field shapes, as a caller choosing one by its case passes.
	const why = (n: number): { reason: string } | { status: number } =>
		n > 0 ? { status: n } : { reason: "refused" };
	log.warn("e", why(1));
	expect(lines()).toHaveLength(4);
});
