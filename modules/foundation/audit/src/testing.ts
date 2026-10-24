import { defineModule } from "@mod/kernel";
import type { z } from "zod";
import { type AuditEvent, audit } from "./contract.ts";
import type { section } from "./section.ts";

export type AuditSettings = z.input<typeof section>;

/** An audit section for tests: no receivers, stated, unless the test names some. */
export function auditConfig(settings: Partial<AuditSettings> = {}) {
	return { audit: { receivers: "none", ...settings } };
}

/** A stand-in for tests of emitters: it keeps every event, stamped with the composition's clock. */
export function auditStandIn() {
	const events: AuditEvent[] = [];
	const module = defineModule({ name: "audit", takes: [] }, (m) => [
		m.provide(audit).by((c) => ({
			record: (event) => {
				events.push({ ...event, at: c.clock.now() });
			},
			lost: () => ({}),
		})),
	]);
	return { module, events };
}
