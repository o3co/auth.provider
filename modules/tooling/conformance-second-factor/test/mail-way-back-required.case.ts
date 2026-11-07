import { generateKeyPairSync } from "node:crypto";
import { areaTarget, sceneOf } from "@mod/conformance";
import { type FakeSmtp, fakeSmtp } from "@mod/conformance/testing";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { secondFactorArea } from "../src/main.ts";
import { issuer, password, running } from "../src/testing.ts";

const pair = generateKeyPairSync("ed25519");
/** The scene under required, its mail sent to the fake SMTP relay, a code by mail kept to mfa-email's default. */
const sceneAt = (smtp: FakeSmtp) =>
	sceneOf(
		keysArea.part({
			signing: {
				kid: "mfa-mail-way-back-required",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: [{ identifier: "gil", password, email: "gil@example.com" }],
			login: { attempts: 100, windowSeconds: 600 },
		}),
		secondFactorArea.part({
			mode: "required",
			mail: { host: smtp.host, port: smtp.port, addsSecondFactor: false },
		}),
	);

// The legacy target binds it all the same (`mfa-required-binds-a-way-back`).
describe.runIf(!areaTarget().differs("mfa-required-binds-a-way-back"))(
	"a code by mail whose proof adds no mfa, under a required second factor",
	() => {
		// Started before the target, which sends to it.
		let smtp: FakeSmtp;
		beforeAll(async () => {
			smtp = await fakeSmtp();
		});
		afterAll(async () => {
			await smtp?.stop();
		});
		const s = running(() => sceneAt(smtp));

		it("is not bound, a first binding of it at login answered 400 unknown kind, and nothing mailed", async () => {
			const { b, answer, transaction } = await s.held("gil");
			expect([answer.status, answer.body.error]).toEqual([403, "mfa_enrollment_required"]);
			const begun = await b.send("POST", "/session/mfa/enrollment", {
				kind: "email",
				transaction_id: transaction,
			});
			expect([begun.status, begun.body.error], JSON.stringify(begun.body)).toEqual([
				400,
				"invalid_request",
			]);
			expect(smtp.latestTo("gil@example.com")).toBeUndefined();
		});
	},
);
