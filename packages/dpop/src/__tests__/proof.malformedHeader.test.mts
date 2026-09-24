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
 * A DPoP proof whose `typ` header cannot even be turned into text is a
 * `typ_mismatch`, not a TypeError out of the parser.
 *
 * The refusal's message was built with `String(header.typ)`, which throws
 * for `{"toString": null}` — so `parseProof` threw a bare TypeError instead
 * of its documented `DPoPError`, and the refusal lost its reason.
 */

import { describe, expect, it } from "vitest";
import { parseProof } from "#/proof.mjs";

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const proofWithTyp = (typ: unknown) =>
	`${b64({ alg: "ES256", typ, jwk: { kty: "EC" } })}.${b64({ htm: "POST", htu: "https://as.example/token", iat: 1, jti: "x" })}.AAAA`;

describe("parseProof — a typ the client made up", () => {
	for (const [label, typ] of [
		["an object whose toString is null", { toString: null }],
		["an object with neither conversion", { toString: 1, valueOf: 1 }],
		["a number", 7],
	] as const) {
		it(`refuses ${label} as a DPoPError typ_mismatch`, async () => {
			await expect(parseProof(proofWithTyp(typ))).rejects.toMatchObject({
				name: "DPoPError",
				reason: "typ_mismatch",
			});
		});
	}
});
