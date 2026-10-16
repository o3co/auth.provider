import { generateKeyPairSync } from "node:crypto";
import { sceneOf } from "@mod/conformance";
import { type FakeSmtp, fakeSmtp } from "@mod/conformance/testing";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { secondFactorArea } from "../src/main.ts";
import { browser, issuer, password, running } from "../src/testing.ts";

const pair = generateKeyPairSync("ed25519");
const users = ["ann", "ben", "cy"];
const addressOf = (user: string) => `${user}@example.com`;
/** The scene, its mail sent to the fake SMTP relay. */
const sceneAt = (smtp: FakeSmtp) =>
	sceneOf(
		keysArea.part({
			signing: {
				kid: "mfa-mail",
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
		secondFactorArea.part({ mode: "optional", mail: { host: smtp.host, port: smtp.port } }),
	);

describe("a code by mail as a second factor", () => {
	// Started before the target, which sends to it.
	let smtp: FakeSmtp;
	beforeAll(async () => {
		smtp = await fakeSmtp();
	});
	afterAll(async () => {
		await smtp?.stop();
	});
	const s = running(() => sceneAt(smtp));

	/** The code of the latest mail to the user, in the given shape. */
	const codeTo = (user: string, shape: RegExp) =>
		shape.exec(smtp.latestTo(addressOf(user))?.text ?? "")?.[1] ?? "";
	const long = /\b([0-9A-Z]{16})\b/;
	const six = /\b([0-9]{6})\b/;

	/** Signs the user in and binds the address the account states, by the code mailed there. */
	const enrol = async (user: string) => {
		const b = browser(() => s.at.base);
		expect((await b.login(user)).status).toBe(200);
		const begun = await b.send("POST", "/session/mfa/enrollment", { kind: "email" });
		const done = await b.send("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: codeTo(user, long),
		});
		return { begun, done };
	};
	/** A password login the factor holds, its code mailed; answers the verification of `proof`. */
	const proved = async (user: string, proof?: (code: string) => string) => {
		const b = browser(() => s.at.base);
		const held = await b.login(user);
		const transaction = String(held.body.transaction);
		const factor = (await b.factors(transaction)).find((f) => f.kind === "email");
		const ids = { transaction_id: transaction, factor_id: factor?.id ?? "" };
		const asked = await b.send("POST", "/session/mfa/challenge", ids);
		const code = codeTo(user, six);
		const answer = await b.send("POST", "/session/mfa/verify", {
			...ids,
			proof: proof ? proof(code) : code,
		});
		return { asked, code, answer };
	};

	it("binds the account's address by the long code mailed there, showing the address masked", async () => {
		const { begun, done } = await enrol("ann");
		expect(begun.status).toBe(200);
		expect(begun.body).toMatchObject({ sent_to: "a***@example.com" });
		expect(smtp.latestTo(addressOf("ann"))?.text).toMatch(long);
		expect(done.status).toBe(200);
	});

	it("lets a login it holds in by the six digits mailed for it", async () => {
		expect((await enrol("ben")).done.status).toBe(200);
		const { asked, code, answer } = await proved("ben");
		expect([asked.status, asked.body.sent_to]).toEqual([200, "b***@example.com"]);
		expect(code).toMatch(/^[0-9]{6}$/);
		expect(answer.status).toBe(200);
	});

	it("refuses a code other than the one mailed, letting nothing in", async () => {
		expect((await enrol("cy")).done.status).toBe(200);
		const wrong = (code: string) => (code === "000000" ? "111111" : "000000");
		const { answer } = await proved("cy", wrong);
		expect([answer.status, answer.body.error]).toEqual([401, "mfa_invalid"]);
	});
});
