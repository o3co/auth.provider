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
import { federationTokenSnapshot } from "../token-snapshot.mjs";

const RECEIVED_AT = Date.parse("2026-09-24T00:00:00Z");

describe("federationTokenSnapshot — one reading of a token response for every adapter", () => {
	it("dates a stated lifetime from when the answer was received, and keeps the seconds as sent", () => {
		const snapshot = federationTokenSnapshot(
			{ access_token: "at", token_type: "bearer", expires_in: 3600 },
			RECEIVED_AT,
		);
		expect(snapshot.expiresIn).toBe(3600);
		expect(snapshot.expiresAt).toEqual(new Date(RECEIVED_AT + 3600 * 1000));
	});

	it("reads an absent expires_in as no stated lifetime: null on both, never an assumed hour", () => {
		// Google and Apple once assumed 3600 here while GitHub and OIDC said
		// null. oauth's federation token route stores null for a refresh that
		// states nothing, and a lifetime nobody stated is not one to invent.
		const snapshot = federationTokenSnapshot({ access_token: "at", token_type: "bearer" });
		expect(snapshot.expiresIn).toBeNull();
		expect(snapshot.expiresAt).toBeNull();
	});

	it("names the token type as the library reported it", () => {
		expect(federationTokenSnapshot({ access_token: "at", token_type: "bearer" }).tokenType).toBe(
			"bearer",
		);
	});

	it("keeps a scope that was sent — an empty one included — and omits one that was not", () => {
		expect(
			federationTokenSnapshot({ access_token: "at", token_type: "bearer", scope: "openid email" })
				.scope,
		).toBe("openid email");
		// Present and empty is an answer: the session route must not read it as
		// "as requested" (RFC 6749 section 3.3).
		const empty = federationTokenSnapshot({ access_token: "at", token_type: "bearer", scope: "" });
		expect(empty.scope).toBe("");
		const silent = federationTokenSnapshot({ access_token: "at", token_type: "bearer" });
		expect("scope" in silent).toBe(false);
	});

	it("carries the refresh token and id_token when they are non-empty strings, and omits them otherwise", () => {
		const full = federationTokenSnapshot({
			access_token: "at",
			token_type: "bearer",
			refresh_token: "rt",
			id_token: "header.payload.signature",
		});
		expect(full.accessToken).toBe("at");
		expect(full.refreshToken).toBe("rt");
		expect(full.idToken).toBe("header.payload.signature");

		const empty = federationTokenSnapshot({
			access_token: "at",
			token_type: "bearer",
			refresh_token: "",
			id_token: "",
		});
		expect("refreshToken" in empty).toBe(false);
		expect("idToken" in empty).toBe(false);
	});
});
