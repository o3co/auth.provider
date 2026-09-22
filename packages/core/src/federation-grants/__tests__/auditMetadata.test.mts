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

const grant = {
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
} as unknown as AuthorizedFederationGrant;

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
});
