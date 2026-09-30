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
 * What the package publishes: the mail senders' modules, the rendering and
 * the SMTP section's schema on its entry; the builder of that section on its
 * testing entry.
 */

import { describe, expect, it } from "vitest";
import * as entry from "#/index.mjs";
import * as testing from "#/testing/index.mjs";

describe("the package's entries", () => {
	it("publishes the senders' modules, the rendering and the SMTP section's schema, and nothing else: no development sender without its module's guard", () => {
		expect(Object.keys(entry).sort()).toEqual([
			"renderStandardMail",
			"standardDevelopmentMailSenderModule",
			"standardSmtpMailSenderConfigSchema",
			"standardSmtpMailSenderModule",
		]);
	});

	it("publishes on its testing entry the builder of its section, and nothing else", () => {
		expect(Object.keys(testing).sort()).toEqual(["standardSmtpMailSenderConfig"]);
	});
});
