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
 * `audit`, where the audit sink's selection, its options and its declared
 * absence were, is presence-only: the selection is a composition root's own
 * (the standalone template's `adapters.auditSink`), the options the sink
 * module's section, and the declared absence core's own list,
 * `core.declaredAbsent`. Core keeps the section as written, whatever it holds,
 * so a root that parses with `AppConfigSchema` before boot still hands it to
 * the refusal of the paths it moved from, and reads nothing of it.
 */

import { describe, expect, it } from "vitest";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { AppConfigSchema } from "../application.schema.mjs";

describe("audit, where the sink's settings were", () => {
	it("is kept as written, whatever it holds", () => {
		const written = {
			sink: { type: "splunk-hec", "splunk-hec": { endpoint: "https://splunk.example/collector" } },
		};
		expect(AppConfigSchema.parse({ ...makeValidAppConfig(), audit: written }).audit).toEqual(
			written,
		);
	});

	it("is absent when omitted", () => {
		expect(AppConfigSchema.parse(makeValidAppConfig()).audit).toBeUndefined();
	});
});
