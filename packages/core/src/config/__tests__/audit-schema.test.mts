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
 * #287 — `audit.sink` has to be a DECLARED top-level section, not merely a
 * key an operator writes in HOCON.
 *
 * `AppConfigSchema` is a plain `z.object`, so it strips what it does not
 * declare. An undeclared section therefore does not fail loudly: the key
 * vanishes between `parseFile` and the composition root, the sink selector
 * reads `undefined`, and the deployment falls back to whatever the default
 * is while the operator's configuration sits in the file looking effective.
 * `federationTokenStore` is the standing example of that failure mode in
 * this repository.
 *
 * Shape only — the literal default lives in `reference.conf` per
 * ADR 2026-04-30.
 */

import { describe, expect, it } from "vitest";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { AppConfigSchema, fullSectionsSchema } from "../application.schema.mjs";

describe("audit schema", () => {
	it("preserves audit.sink.type through a full AppConfigSchema parse", () => {
		const parsed = AppConfigSchema.parse({
			...makeValidAppConfig(),
			audit: { sink: { type: "console" } },
		});
		expect(parsed.audit?.sink.type).toBe("console");
	});

	it("keeps the sink type open so a deployment can register its own", () => {
		// The selector names a builder in an AdapterFactory the composition
		// root owns. Pinning an enum here would make every out-of-tree sink a
		// schema change in this package.
		const parsed = fullSectionsSchema.shape.audit.parse({ sink: { type: "splunk-hec" } });
		expect(parsed?.sink.type).toBe("splunk-hec");
	});

	it("carries the selected sink's own options alongside the selector", () => {
		// Same `{ type, [type]: { … } }` shape as `repositories.*` and
		// `session.storage`, which the composition root flattens before handing
		// the slice to the factory. Without passthrough the options would be
		// stripped and every out-of-tree sink would boot unconfigured.
		const parsed = fullSectionsSchema.shape.audit.parse({
			sink: {
				type: "splunk-hec",
				"splunk-hec": { endpoint: "https://splunk.example/services/collector" },
			},
		});
		const sink = parsed?.sink as Record<string, Record<string, unknown>> | undefined;
		expect(sink?.["splunk-hec"]?.endpoint).toBe("https://splunk.example/services/collector");
	});

	it("accepts the section being absent (composition root supplies the safe default)", () => {
		// Absence must not be a boot failure for a hand-built config, but it
		// must also not mean "no sink" — that is the composition root's
		// concern, pinned in the standalone template's own tests.
		expect(fullSectionsSchema.shape.audit.safeParse(undefined).success).toBe(true);
	});
});
