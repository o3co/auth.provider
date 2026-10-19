import { generateKeyPairSync, randomBytes } from "node:crypto";
import { areaTarget, auditEvents, type Started, sceneOf } from "@mod/conformance";
import { keysArea } from "@mod/conformance-keys";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { identityArea, ledgerRevocation } from "../src/main.ts";

const issuer = "https://issuer.example";
const credential = randomBytes(32).toString("base64url");
const pair = generateKeyPairSync("ed25519");
const scene = sceneOf(
	keysArea.part({
		signing: {
			kid: "revocation",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	}),
	identityArea.part({
		origin: issuer,
		users: [{ identifier: "alice", password: "correct horse battery" }],
		revocations: { credential, sources: ["198.51.100.0/24"] },
	}),
);

let running: Started;
let base = "";
let sender = 0;
/** Each test sends from its own address in the ledger's block, so the windows are per test. */
const nextSender = () => `198.51.100.${++sender}`;

/** The ledger's revocation of `subject`, as the proxy forwards it: https, from `from`, unless a test says. */
async function revoke(
	subject: string,
	from: string,
	headers: Record<string, string> = { authorization: `Bearer ${credential}` },
) {
	const res = await fetch(`${base}/ledger/subject-revocations`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for": from,
			...headers,
		},
		body: JSON.stringify({ subject }),
	});
	return {
		status: res.status,
		challenge: res.headers.get("www-authenticate"),
		json: await res.json().catch(() => undefined),
	};
}

describe.runIf(areaTarget().can(ledgerRevocation))("a subject the ledger revokes over HTTP", () => {
	beforeAll(async () => {
		running = await areaTarget().start(scene);
		if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
		base = running.baseUrl;
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
	});

	it("revokes a subject sent from a listed source with the credential, and again when resent", async () => {
		const from = nextSender();
		const done = { status: 200, json: { complete: true } };
		expect(await revoke("alice", from)).toMatchObject(done);
		expect(await revoke("alice", from)).toMatchObject(done);
		// A subject no user holds is answered alike, so the answer tells no one who is a user.
		expect(await revoke("nobody", from)).toMatchObject(done);
	});

	it("answers a missing and a wrong credential alike, with a Bearer challenge", async () => {
		const from = nextSender();
		const wrong = `Bearer ${randomBytes(32).toString("base64url")}`;
		const answers = [
			await revoke("alice", from, {}),
			await revoke("alice", from, { authorization: wrong }),
		];
		for (const answer of answers) {
			expect(answer).toMatchObject({ status: 401, challenge: expect.stringMatching(/^Bearer/) });
		}
		expect(answers[0]?.json).toEqual(answers[1]?.json);
	});

	it("refuses a source outside the list whatever the credential, and a request not told as https", async () => {
		const outside = { status: 403, json: { error: "forbidden_source" } };
		expect(await revoke("alice", "203.0.113.7")).toMatchObject(outside);
		expect(await revoke("alice", "203.0.113.7", {})).toMatchObject(outside);
		const plain = await revoke("alice", nextSender(), {
			authorization: `Bearer ${credential}`,
			"x-forwarded-proto": "http",
		});
		expect(plain).toMatchObject({ status: 403, json: { error: "https_required" } });
	});

	it.runIf(areaTarget().can(auditEvents.need))(
		"records a revocation with its subject and source, and a refusal without a subject",
		async () => {
			const trail = auditEvents.of(running);
			const from = nextSender();
			const done = await trail.during(() => revoke("alice", from));
			expect(done.events).toEqual([
				{
					kind: "subject.revocation.requested",
					at: expect.any(Number),
					subject: "alice",
					attributes: { delegations: "end", outcome: "complete", source: from },
				},
			]);
			const refused = await trail.during(() => revoke("alice", from, {}));
			expect(refused.events).toEqual([
				{
					kind: "subject.revocation.denied",
					at: expect.any(Number),
					attributes: { reason: "unauthenticated", source: from },
				},
			]);
			expect(JSON.stringify([done.events, refused.events])).not.toContain(credential);
		},
	);
});
