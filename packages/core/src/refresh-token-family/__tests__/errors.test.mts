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
import { describe, expect, it } from "vitest";
import { RefreshTokenStorageError, type RefreshTokenStorageErrorReason } from "../errors.mjs";

describe("RefreshTokenStorageError", () => {
	it("constructs with reason and default message", () => {
		const err = new RefreshTokenStorageError({ reason: "duplicate-family" });
		expect(err).toBeInstanceOf(Error);
		expect(err.name).toBe("RefreshTokenStorageError");
		expect(err.reason).toBe("duplicate-family");
		expect(err.message).toBe("RefreshTokenStorageError: duplicate-family");
	});

	it("uses custom message when provided", () => {
		const err = new RefreshTokenStorageError({
			reason: "expired-at-issue",
			message: "TTL exhausted at register time",
		});
		expect(err.reason).toBe("expired-at-issue");
		expect(err.message).toBe("TTL exhausted at register time");
	});

	it("captures cause when provided", () => {
		const cause = new Error("underlying redis failure");
		const err = new RefreshTokenStorageError({
			reason: "conflict-exhausted",
			cause,
		});
		expect(err.reason).toBe("conflict-exhausted");
		expect(err.cause).toBe(cause);
	});

	it("does not materialise own-property `cause` when not provided", () => {
		const err = new RefreshTokenStorageError({ reason: "duplicate-family" });
		expect(Object.hasOwn(err, "cause")).toBe(false);
	});

	it("supports reason narrowing via instanceof + reason", () => {
		const err: unknown = new RefreshTokenStorageError({ reason: "expired-at-issue" });
		if (err instanceof RefreshTokenStorageError && err.reason === "expired-at-issue") {
			const narrowed: "expired-at-issue" = err.reason;
			expect(narrowed).toBe("expired-at-issue");
		} else {
			throw new Error("type-narrowing failed");
		}
	});

	it("reason union has exactly 3 members", () => {
		const all: RefreshTokenStorageErrorReason[] = [
			"duplicate-family",
			"expired-at-issue",
			"conflict-exhausted",
		];
		expect(all).toHaveLength(3);
	});
});
