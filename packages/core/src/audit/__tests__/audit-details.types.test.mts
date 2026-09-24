/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * `AuditEvent.details` gives its two error-bearing keys one type each, so the
 * compiler refuses an emission that would give a sink a second one: a sink
 * that fixes a field's type on first sight (Elasticsearch dynamic mapping, a
 * BigQuery schema, a Datadog facet) drops whichever shape arrives second.
 *
 * Type-level only: these assertions fire under vitest's typecheck mode, which
 * `vitest.config.mts` and `tsconfig.test.json` both list this file for.
 */

import { describe, expectTypeOf, it } from "vitest";
import type { AuditedError } from "#/audit/auditedError.mjs";
import type { AuditEvent } from "#/audit/types.mjs";

type Details = NonNullable<AuditEvent["details"]>;

describe("AuditEvent.details", () => {
	it("types error as a string and cause as an audited error", () => {
		expectTypeOf<Details["error"]>().toEqualTypeOf<string | undefined>();
		expectTypeOf<Details["cause"]>().toEqualTypeOf<AuditedError | undefined>();
	});

	it("refuses an error that is not a string", () => {
		const event: AuditEvent = {
			timestamp: new Date(0),
			type: "custom.example",
			details: {
				// @ts-expect-error — an error the event reports goes under `cause`.
				error: { name: "Error" },
			},
		};
		expectTypeOf(event).toEqualTypeOf<AuditEvent>();
	});

	it("keeps an audited error's code a string", () => {
		expectTypeOf<AuditedError["code"]>().toEqualTypeOf<string | undefined>();
	});
});
