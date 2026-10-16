import { randomBytes } from "node:crypto";
import type { z } from "zod";
import type { section } from "./section.ts";

export type AuditHttpSettings = z.input<typeof section>;

const testAuthorization = `Bearer ${randomBytes(24).toString("base64url")}`;

/** The audit-http part of a test's configuration: an https URL and an Authorization value, unless the test sets them. */
export function auditHttpConfig(settings: Partial<AuditHttpSettings> = {}) {
	return {
		"audit-http": {
			url: "https://audit.example/events",
			authorization: testAuthorization,
			...settings,
		},
	};
}
