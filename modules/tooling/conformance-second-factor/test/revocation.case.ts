import { generateKeyPairSync, randomBytes } from "node:crypto";
import { areaTarget, sceneOf } from "@mod/conformance";
import { identityArea, ledgerRevocation } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { describe, expect, it } from "vitest";
import { secondFactorArea } from "../src/main.ts";
import { issuer, password, running, sessionCookie, totp } from "../src/testing.ts";

const credential = randomBytes(32).toString("base64url");
const pair = generateKeyPairSync("ed25519");
const scene = sceneOf(
	keysArea.part({
		signing: {
			kid: "revoked",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	}),
	identityArea.part({
		origin: issuer,
		users: [{ identifier: "alice", password }],
		revocations: { credential, sources: ["198.51.100.0/24"] },
	}),
	secondFactorArea.part({ mode: "optional" }),
);

describe.runIf(areaTarget().can(ledgerRevocation))(
	"G. second factor: a subject the ledger revokes",
	() => {
		const s = running(scene);

		/** The ledger's revocation of a subject, from its block over https, as its proxy forwards it. */
		const revoke = async (subject: string) => {
			const res = await fetch(`${s.at.base}/ledger/subject-revocations`, {
				method: "POST",
				headers: {
					"content-type": "application/json",
					"x-forwarded-proto": "https",
					"x-forwarded-for": "198.51.100.30",
					authorization: `Bearer ${credential}`,
				},
				body: JSON.stringify({ subject }),
			});
			return res.status;
		};

		it("ends a login a second factor holds: its transaction answers login_required, and the right code opens no session", async () => {
			const { secret } = await s.enrol("alice");
			const { b, transaction } = await s.held("alice");
			const header = { "mfa-transaction": transaction };
			const factor = (await b.factors(transaction)).find((f) => f.kind === "totp");
			expect(factor).toBeDefined();
			expect(await revoke("alice")).toBe(200);
			const shown = await b.send("GET", "/session/mfa/transaction", {}, header);
			expect([shown.status, shown.body.error]).toEqual([401, "login_required"]);
			const proved = await b.send("POST", "/session/mfa/verify", {
				transaction_id: transaction,
				factor_id: factor?.id ?? "",
				proof: totp(secret, 1),
			});
			expect(proved.status).toBe(401);
			expect(sessionCookie(b.jar)).toBeFalsy();
		});
	},
);
