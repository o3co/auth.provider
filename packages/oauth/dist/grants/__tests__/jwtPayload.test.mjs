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
import { decodeJwtPayload } from "#/grants/_jwtPayload.mjs";
describe("decodeJwtPayload", () => {
    it("returns the decoded payload object for a well-formed JWT", () => {
        const payload = { sub: "user-1", exp: 1234567890, jti: "abc" };
        const base64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
        const token = `header.${base64}.signature`;
        expect(decodeJwtPayload(token)).toEqual(payload);
    });
    it("returns empty object for malformed input (no dot)", () => {
        expect(decodeJwtPayload("not-a-jwt")).toEqual({});
    });
    it("returns empty object when payload is not valid JSON", () => {
        const token = `header.${Buffer.from("not json").toString("base64url")}.sig`;
        expect(decodeJwtPayload(token)).toEqual({});
    });
});
