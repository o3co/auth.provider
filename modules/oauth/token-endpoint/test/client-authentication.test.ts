import type { AuditRecord } from "@mod/audit";
import type { Authentication, Client, Clients } from "@mod/clients";
import { testRequest } from "@mod/http/testing";
import { describe, expect, it } from "vitest";
import declared from "../src/audit-events.ts";
import { authenticateClient } from "../src/contract.ts";

type Refused = Extract<Authentication, { kind: "refused" }>["reason"];

/** `clients` answering `authenticate` with `answer` alone. */
const answering = (answer: Authentication) =>
	({ authenticate: async () => answer }) as unknown as Clients;

const refusing = (reason: Refused) => answering({ kind: "refused", reason, challenges: [] });

/** An audit keeping what is recorded. */
function recording() {
	const records: AuditRecord[] = [];
	return { records, audit: { record: (event: AuditRecord) => void records.push(event) } };
}

const reasons: readonly Refused[] = [
	"no_credentials",
	"multiple_methods",
	"malformed_credentials",
	"unknown_client",
	"wrong_method",
	"bad_credentials",
	"invalid_record",
];

describe("authenticateClient", () => {
	it("records each refusal once, with its reason and the source, and no client or credential", async () => {
		for (const reason of reasons) {
			const { records, audit } = recording();
			const request = testRequest({
				method: "POST",
				form: new Map([
					["client_id", ["claimed"]],
					["client_secret", ["s3cret"]],
				]),
			});
			const answered = await authenticateClient(refusing(reason), request, audit);
			expect(answered.kind, reason).toBe("refused");
			expect(records, reason).toEqual([
				{ kind: "client.authentication.failure", attributes: { source: "127.0.0.1", reason } },
			]);
		}
	});

	it("names no source it could not determine", async () => {
		const { records, audit } = recording();
		const request = testRequest({ source: { determined: false } });
		await authenticateClient(refusing("bad_credentials"), request, audit);
		expect(records).toEqual([
			{ kind: "client.authentication.failure", attributes: { reason: "bad_credentials" } },
		]);
	});

	it("records nothing for a client authenticated", async () => {
		const { records, audit } = recording();
		const client = { id: "c" } as Client;
		const clients = answering({ kind: "authenticated", client, challenges: [] });
		expect((await authenticateClient(clients, testRequest(), audit)).kind).toBe("client");
		expect(records).toEqual([]);
	});

	it("declares the failure with the attributes it records", () => {
		expect(declared["client.authentication.failure"].attributes).toEqual(["source", "reason"]);
		for (const reason of reasons)
			expect(declared["client.authentication.failure"].when).toContain(`\`${reason}\``);
	});
});
