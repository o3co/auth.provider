import { generateKeyPairSync } from "node:crypto";
import { areaTarget, sceneOf } from "@mod/conformance";
import { type FakeSmtp, fakeSmtp } from "@mod/conformance/testing";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { secondFactorArea } from "../src/main.ts";
import { browser, issuer, password, running, totp } from "../src/testing.ts";

const pair = generateKeyPairSync("ed25519");
const users = ["dee", "eve"];
const addressOf = (user: string) => `${user}@example.com`;
/** The scene, its mail sent to the fake SMTP relay, a code by mail kept to mfa-email's default. */
const sceneAt = (smtp: FakeSmtp) =>
	sceneOf(
		keysArea.part({
			signing: {
				kid: "mfa-mail-way-back",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: users.map((identifier) => ({ identifier, password, email: addressOf(identifier) })),
			login: { attempts: 100, windowSeconds: 600 },
		}),
		secondFactorArea.part({
			mode: "optional",
			mail: { host: smtp.host, port: smtp.port, addsSecondFactor: false },
		}),
	);

describe("a code by mail kept as a way back, its proof adding no mfa (mfa-email's default)", () => {
	// Started before the target, which sends to it.
	let smtp: FakeSmtp;
	beforeAll(async () => {
		smtp = await fakeSmtp();
	});
	afterAll(async () => {
		await smtp?.stop();
	});
	const s = running(() => sceneAt(smtp));
	const codeTo = (user: string, shape: RegExp) =>
		shape.exec(smtp.latestTo(addressOf(user))?.text ?? "")?.[1] ?? "";
	const long = /\b([0-9A-Z]{16})\b/;
	const six = /\b([0-9]{6})\b/;

	/** A password login a factor holds, let in by the factor of `kind` with `proof`; answers the browser. */
	const letIn = async (user: string, kind: string, proof: () => Promise<string> | string) => {
		const b = browser(() => s.at.base);
		const held = await b.login(user);
		expect(held.status, "held").toBe(403);
		const transaction = String(held.body.transaction);
		const factor = (await b.factors(transaction)).find((f) => f.kind === kind);
		const ids = { transaction_id: transaction, factor_id: factor?.id ?? "" };
		if (kind === "email") await b.send("POST", "/session/mfa/challenge", ids);
		const verified = await b.send("POST", "/session/mfa/verify", { ...ids, proof: await proof() });
		expect(verified.status, JSON.stringify(verified.body)).toBe(200);
		return b;
	};

	it("is bound from a session, and a login it lets in is no second factor proved: changing credentials asks a step-up", async () => {
		const { secret } = await s.enrol("dee");
		// A session the TOTP proved: it may change credentials, binding a code by mail.
		const proved = await letIn("dee", "totp", () => totp(secret, 1));
		const begun = await proved.send("POST", "/session/mfa/enrollment", { kind: "email" });
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		const done = await proved.send("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: codeTo("dee", long),
		});
		expect(done.status, JSON.stringify(done.body)).toBe(200);
		// A login the code by mail lets in carries no mfa: the same change asks a step-up of it.
		const byMail = await letIn("dee", "email", () => codeTo("dee", six));
		const asked = await byMail.send("POST", "/session/mfa/enrollment", { kind: "totp" });
		expect(asked.status, JSON.stringify(asked.body)).toBe(403);
		expect(asked.body).toMatchObject({ error: "step_up_required" });
	});

	it("is bound as a subject's first factor, no recovery codes made where nothing counts, and then holds its logins", async () => {
		const b = browser(() => s.at.base);
		expect((await b.login("eve")).status).toBe(200);
		const begun = await b.send("POST", "/session/mfa/enrollment", { kind: "email" });
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		const done = await b.send("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: codeTo("eve", long),
		});
		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body).toMatchObject({ factor: { kind: "email" } });
		if (!areaTarget().differs("mfa-codes-for-a-first-way-back")) {
			expect(done.body).not.toHaveProperty("recovery_codes");
		}
		// The code by mail now holds a password login, and lets it in.
		await letIn("eve", "email", () => codeTo("eve", six));
	});
});
