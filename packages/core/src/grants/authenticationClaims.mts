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
 * The authentication claims a token may carry (#481): `amr` (RFC 8176) and
 * `acr` (OIDC Core §2), read in one shape by every grant that stamps them.
 *
 * They reach a token from a recorded `UserSession` (a password login, a
 * federation login recording the upstream IdP's `amr` as it arrived), from the
 * code record, or from a refresh token a previous grant minted. A refresh does
 * not repeat the authentication, so the claims are copied forward — and a claim
 * copied forward is a claim vouched for again. One predicate is what keeps a
 * grant from stamping an `amr: []` that the next grant drops, so a resource
 * server gating on `amr` sees one answer for one authentication.
 */

/** `amr` as a token may carry it — a non-empty array of non-empty strings, copied — else undefined. */
export function wellFormedAmr(value: unknown): readonly string[] | undefined {
	if (!Array.isArray(value) || value.length === 0) return undefined;
	if (!value.every((v) => typeof v === "string" && v.length > 0)) return undefined;
	return [...(value as string[])];
}

/** `acr` as a token may carry it — a non-empty string — else undefined. */
export function wellFormedAcr(value: unknown): string | undefined {
	return typeof value === "string" && value.length > 0 ? value : undefined;
}
