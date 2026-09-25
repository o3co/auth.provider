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
import { federationGrantAuditMetadata } from "#/federation-grants/auditMetadata.mjs";
import type { AuthorizedFederationGrant } from "#/federation-grants/types.mjs";

const AT = new Date("2026-09-22T00:00:00.000Z");

const grant: AuthorizedFederationGrant = {
	id: "g-1",
	status: "active",
	subject: "u-1",
	clientId: "agent",
	connection: "files",
	createdAt: AT,
	version: 1,
	identityRevision: "i",
	authorizationRevision: "a",
	upstream: { issuer: "https://issuer.example", subject: "grant-A" },
	scopes: ["openid", "Files.Read"],
	consent: { at: AT, sid: "sid-1", scopes: ["openid", "Files.Read"] },
	authorizedAt: AT,
	expiresAt: new Date(AT.getTime() + 86_400_000),
	resource: undefined,
	lastUsedAt: undefined,
	ineligible: undefined,
	refreshFailure: undefined,
};

describe("federationGrantAuditMetadata (#593, D18)", () => {
	it("carries the upstream identity as issuer and subject only, whatever else the record's object holds (#611)", () => {
		// Check 5 carries verified claims beside the subject; an event is not a
		// place they may reach, even through a record object that picked them up.
		const metadata = federationGrantAuditMetadata({
			...grant,
			upstream: { ...grant.upstream, claims: { oid: "sentinel-oid" } },
		} as unknown as AuthorizedFederationGrant);
		expect(metadata.upstream).toStrictEqual({
			issuer: "https://issuer.example",
			subject: "grant-A",
		});
		expect(JSON.stringify(metadata)).not.toContain("sentinel");
	});

	it("carries the upstream subject sanitised and capped: the IdP wrote it", () => {
		// The ID token's `sub`, stored as the IdP sent it; every emitter —
		// core's retrieval and revocation, whose `audit` seam a composer may
		// fill with its own function, and the routes' bridges — takes it from
		// here.
		const metadata = federationGrantAuditMetadata({
			...grant,
			upstream: {
				issuer: grant.upstream.issuer,
				subject: `sub\r\nFORGED\u0085\u2028\u202e${"s".repeat(10_000)}`,
			},
		});
		const subject = metadata.upstream?.subject ?? "";
		expect({
			head: subject.slice(0, 11),
			// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be audited.
			unsafe: /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/.test(subject),
			within200: subject.length <= 200,
		}).toEqual({ head: "sub??FORGED", unsafe: false, within200: true });
	});

	it("carries an ordinary upstream subject exactly", () => {
		expect(federationGrantAuditMetadata(grant).upstream?.subject).toBe("grant-A");
	});
});
