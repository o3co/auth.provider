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
 * `lineSafeText`: the filter `loggableError` applies to a message, for a
 * package that logs text a peer wrote which is not an error's — a
 * certificate's subject, a URL a certificate names, a responder's
 * Content-Type — and must keep a non-ASCII name legible (so not
 * `auditErrorText`'s RFC 6749 set).
 */

import { describe, expect, it } from "vitest";
import { lineSafeText } from "#/logging/loggableError.mjs";

describe("lineSafeText", () => {
	it("replaces C0, DEL, C1, the line separators and the bidi controls with ?", () => {
		expect(lineSafeText("CN=a\r\nb\u0085c\u2028d\u202ee\u2066f\u007fg")).toBe("CN=a??b?c?d?e?f?g");
	});

	it("keeps a non-ASCII name, quotes and backslashes as they are", () => {
		const subject = 'CN=Zoë Müller,O=株式会社 "Example" \\ Ltd';
		expect(lineSafeText(subject)).toBe(subject);
	});

	it("caps at 256 characters by default, marking the cut", () => {
		const text = lineSafeText(`x${"y".repeat(10_000)}`);
		expect({ length: text.length, tail: text.slice(-3) }).toEqual({ length: 256, tail: "..." });
	});

	it("caps at the length it is told", () => {
		expect(lineSafeText("abcdefghij", 8)).toBe("abcde...");
		expect(lineSafeText("abcdefgh", 8)).toBe("abcdefgh");
	});

	it("answers undefined for a value that is not a string", () => {
		expect(lineSafeText(undefined)).toBeUndefined();
		expect(lineSafeText(42)).toBeUndefined();
	});
});
