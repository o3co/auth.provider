import type { AuditRecord } from "@mod/audit";
import { testRequest } from "@mod/http/testing";
import { describe, expect, it } from "vitest";
import declared from "../src/audit-events.ts";
import { type Authentication, recordRefusedAuthentication } from "../src/contract.ts";

type Refused = Extract<Authentication, { kind: "refused" }>;

const reasons: readonly Refused["reason"][] = [
	"no_credentials",
	"multiple_methods",
	"malformed_credentials",
	"unknown_client",
	"wrong_method",
	"bad_credentials",
	"invalid_record",
];

/** An audit keeping what is recorded. */
function recording() {
	const records: AuditRecord[] = [];
	return { records, audit: { record: (event: AuditRecord) => void records.push(event) } };
}

describe("recordRefusedAuthentication", () => {
	it("records a refusal once, with its reason and the source, and no client or credential", () => {
		for (const reason of reasons) {
			const { records, audit } = recording();
			const request = testRequest({
				method: "POST",
				form: new Map([
					["client_id", ["claimed"]],
					["client_secret", ["s3cret"]],
				]),
			});
			recordRefusedAuthentication(audit, request, { kind: "refused", reason, challenges: [] });
			expect(records, reason).toEqual([
				{ kind: "client.authentication.failure", attributes: { source: "127.0.0.1", reason } },
			]);
		}
	});

	it("names no source it could not determine", () => {
		const { records, audit } = recording();
		const request = testRequest({ source: { determined: false } });
		recordRefusedAuthentication(audit, request, {
			kind: "refused",
			reason: "bad_credentials",
			challenges: [],
		});
		expect(records).toEqual([
			{ kind: "client.authentication.failure", attributes: { reason: "bad_credentials" } },
		]);
	});

	it("declares the event with the attributes it records, naming each reason", () => {
		const event = declared["client.authentication.failure"];
		expect(event.attributes).toEqual(["source", "reason"]);
		for (const reason of reasons) expect(event.when).toContain(`\`${reason}\``);
	});
});
