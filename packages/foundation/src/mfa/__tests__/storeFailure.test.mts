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
 * What the Store adapter throws when an MFA endpoint's answer is not one the
 * contract gives it: nothing the Store sent — its body, status text or
 * headers — reaches the error's message, its fields, a log line's projection
 * or an audit event's; the body is released unread. The error carries no
 * `status` an HTTP layer would answer with, so the client gets the
 * provider's generic answer whatever the Store said, and cannot tell an
 * unreadable record from any other outage. The subject and factor id an
 * unexpected version names are sanitised and bounded.
 */

import { inspect } from "node:util";
import { auditedError, loggableError } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	MfaStoreError,
	mfaStoreMalformedAnswer,
	mfaStoreStatusError,
	mfaStoreUnreadableRecord,
	mfaStoreVersionSkipped,
} from "#/index.mjs";

/** Text the Store wrote, which must reach nothing the error carries. */
const MARKER = "STORE-WROTE-THIS";

const URL_WITH_SECRETS = "https://store.example/mfa/update?api_key=QUERY-SECRET#FRAGMENT-SECRET";

/** Every form in which an error leaves the adapter: its message, its fields, how it prints, and its projections. */
const everyForm = (error: Error): string =>
	[
		error.message,
		JSON.stringify(error),
		JSON.stringify(
			Object.getOwnPropertyNames(error).map((key) => [key, String((error as never)[key])]),
		),
		inspect(error, { depth: 5 }),
		JSON.stringify(loggableError(error)),
		JSON.stringify(auditedError(error)),
	].join("\n");

/** A Store answer carrying `MARKER` everywhere it can, and a body that records whether it was read or released. */
function hostileAnswer(status: number) {
	const seen = { read: false, released: false };
	const body = new ReadableStream<Uint8Array>({
		pull(controller) {
			seen.read = true;
			controller.enqueue(new TextEncoder().encode(`{"error":"${MARKER}"}`));
			controller.close();
		},
		cancel() {
			seen.released = true;
		},
	});
	const response = new Response(body, {
		status,
		statusText: MARKER,
		headers: {
			"Content-Type": "application/json",
			"X-Store-Error": MARKER,
			"WWW-Authenticate": `Bearer error_description="${MARKER}"`,
			Location: `https://${MARKER}.example/`,
		},
	});
	return { response, seen };
}

/** Whether an HTTP layer — Express, http-errors, a terminal handler — could read a status to answer with off `error`. */
const answerable = (error: object): string[] =>
	["status", "statusCode", "expose", "headers", "body", "cause"].filter((key) => key in error);

describe("mfaStoreStatusError", () => {
	it("names the operation, the endpoint by origin and path, and the status — nothing the Store wrote", async () => {
		for (const status of [500, 502, 503, 400, 404, 409, 302, 418]) {
			const { response } = hostileAnswer(status);
			const error = mfaStoreStatusError("update", URL_WITH_SECRETS, response);
			expect(error).toBeInstanceOf(MfaStoreError);
			expect(error.name).toBe("MfaStoreError");
			expect(error.message).toContain("update");
			expect(error.message).toContain("https://store.example/mfa/update");
			expect(error.message).toContain(`HTTP ${status}`);
			const forms = everyForm(error);
			expect(forms).not.toContain(MARKER);
			expect(forms).not.toContain("QUERY-SECRET");
			expect(forms).not.toContain("FRAGMENT-SECRET");
		}
	});

	it("releases the body unread", async () => {
		const { response, seen } = hostileAnswer(500);
		mfaStoreStatusError("list", "https://store.example/mfa/list", response);
		await new Promise((resolve) => setTimeout(resolve, 0));
		expect(seen.read).toBe(false);
		expect(seen.released).toBe(true);
	});

	it("reads markMfaEnrolled's 404 as a subject the Store does not hold, and any other status as unexpected", () => {
		const unknown = mfaStoreStatusError(
			"markMfaEnrolled",
			"https://store.example/mfa/enrolled",
			hostileAnswer(404).response,
		);
		expect(unknown.reason).toBe("unknown_subject");
		expect(unknown.message).toContain("holds no such subject");
		for (const [operation, status] of [
			["markMfaEnrolled", 500],
			["list", 404],
			["create", 404],
		] as const) {
			const error = mfaStoreStatusError(
				operation,
				"https://store.example/x",
				hostileAnswer(status).response,
			);
			expect(error.reason, `${operation} ${status}`).toBe("unexpected_status");
		}
	});

	it("keeps the reason, the operation and the Store's status as fields a log line carries, and no status to answer with", () => {
		const error = mfaStoreStatusError(
			"delete",
			"https://store.example/x",
			hostileAnswer(503).response,
		);
		expect(error.reason).toBe("unexpected_status");
		expect(error.operation).toBe("delete");
		expect(error.storeStatus).toBe(503);
		expect(loggableError(error)).toMatchObject({
			name: "MfaStoreError",
			reason: "unexpected_status",
			storeStatus: 503,
		});
		expect(answerable(error)).toEqual([]);
	});
});

describe("the other failures of an answer", () => {
	it("a body that is not the contract's names the operation and the endpoint by origin and path", () => {
		const error = mfaStoreMalformedAnswer("list", URL_WITH_SECRETS);
		expect(error.reason).toBe("malformed_answer");
		expect(error.operation).toBe("list");
		expect(error.storeStatus).toBeUndefined();
		expect(error.message).toContain("https://store.example/mfa/update");
		expect(everyForm(error)).not.toContain("QUERY-SECRET");
		expect(answerable(error)).toEqual([]);
	});

	it("an unreadable record is an error of the list, never read as none", () => {
		const error = mfaStoreUnreadableRecord("https://store.example/mfa/list");
		expect(error.reason).toBe("unreadable_record");
		expect(error.operation).toBe("list");
		expect(error.message).toContain("never read as none");
		expect(answerable(error)).toEqual([]);
	});

	it("a version other than the expected one plus one is one error naming the subject and the factor id", () => {
		const error = mfaStoreVersionSkipped("https://store.example/mfa/update", {
			subject: "user-1",
			id: "factor-1",
			expectedVersion: 41,
		});
		expect(error.reason).toBe("version_skipped");
		expect(error.operation).toBe("update");
		expect(error.message).toContain("user-1");
		expect(error.message).toContain("factor-1");
		expect(error.message).toContain("42");
		expect(error.message.split("\n")).toHaveLength(1);
		expect(answerable(error)).toEqual([]);
	});

	it("sanitises and bounds the subject and factor id it names: one line, printable, at most 200 characters each", () => {
		const hostile = `a\r\nforged: line\u2028\u202e${"x".repeat(10_000)}`;
		const error = mfaStoreVersionSkipped("https://store.example/mfa/update", {
			subject: hostile,
			id: hostile,
			expectedVersion: 1,
		});
		expect(error.message).not.toMatch(/[\r\n\u2028\u2029\u202e]/);
		expect(error.message).not.toContain("x".repeat(200));
		expect(error.message.match(/a\?\?forged: line\?\?x+\.\.\./g)).toHaveLength(2);
	});
});
