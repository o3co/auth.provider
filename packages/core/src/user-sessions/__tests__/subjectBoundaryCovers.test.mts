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
 * `subjectBoundaryCovers`: the one read of a subject's revocation boundary a
 * caller outside the verifier makes before it signs, answered by `verifyJwt`'s
 * rule for `iat`.
 */

import { describe, expect, it } from "vitest";
import { subjectBoundaryCovers } from "#/user-sessions/subjectRevocationBoundary.mjs";
import type { SubjectRevocation } from "#/user-sessions/types.mjs";

/** A boundary with a sub-second part, as a store records one. */
const BOUNDARY = new Date(1_790_000_000_300);
const BOUNDARY_SECOND = 1_790_000_000;

const answering = (
	boundary: unknown,
): Pick<SubjectRevocation, "revokedBefore"> & { readonly asked: string[] } => {
	const asked: string[] = [];
	return {
		asked,
		revokedBefore: async (subject: string) => {
			asked.push(subject);
			return boundary as Date | null;
		},
	};
};

describe("subjectBoundaryCovers", () => {
	it("covers an issue time before the boundary, in its second, or within the allowance after it", async () => {
		const revocation = answering(BOUNDARY);
		for (const issuedAt of [BOUNDARY_SECOND - 60, BOUNDARY_SECOND, BOUNDARY_SECOND + 1]) {
			expect(await subjectBoundaryCovers(revocation, "user-1", issuedAt)).toEqual({
				answer: "covered",
			});
		}
		expect(revocation.asked).toEqual(["user-1", "user-1", "user-1"]);
	});

	it("clears an issue time after the boundary plus the allowance, as verifyJwt does", async () => {
		expect(await subjectBoundaryCovers(answering(BOUNDARY), "user-1", BOUNDARY_SECOND + 2)).toEqual(
			{ answer: "clear" },
		);
		// Truncated to its second, as `iat` is compared.
		expect(
			await subjectBoundaryCovers(answering(BOUNDARY), "user-1", BOUNDARY_SECOND + 1.9),
		).toEqual({ answer: "covered" });
	});

	it("clears anything while no boundary is in force, an absent issue time included", async () => {
		for (const issuedAt of [BOUNDARY_SECOND - 60, undefined, Number.NaN]) {
			expect(await subjectBoundaryCovers(answering(null), "user-1", issuedAt)).toEqual({
				answer: "clear",
			});
		}
	});

	it("covers an absent or unusable issue time while a boundary is in force", async () => {
		for (const issuedAt of [undefined, Number.NaN, Number.POSITIVE_INFINITY, "1790000100"]) {
			expect(
				await subjectBoundaryCovers(answering(BOUNDARY), "user-1", issuedAt as number | undefined),
			).toEqual({ answer: "covered" });
		}
	});

	it("is unavailable when the boundary cannot be read, carrying the cause", async () => {
		const cause = new Error("ECONNREFUSED");
		const result = await subjectBoundaryCovers(
			{
				revokedBefore: async () => {
					throw cause;
				},
			},
			"user-1",
			BOUNDARY_SECOND + 60,
		);
		expect(result).toEqual({ answer: "unavailable", cause });
	});

	it("is unavailable for a boundary that is not a valid date, whatever the issue time", async () => {
		for (const boundary of ["2026-01-01", new Date(Number.NaN), 1_790_000_000_000, {}]) {
			for (const issuedAt of [BOUNDARY_SECOND + 60, undefined]) {
				const result = await subjectBoundaryCovers(answering(boundary), "user-1", issuedAt);
				expect(result.answer, `${String(boundary)} / ${String(issuedAt)}`).toBe("unavailable");
			}
		}
	});
});
