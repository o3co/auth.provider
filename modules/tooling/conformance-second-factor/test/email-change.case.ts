import { generateKeyPairSync, randomBytes } from "node:crypto";
import { areaTarget, auditEvents, type Fake, fakeHttp, sceneOf } from "@mod/conformance";
import { type FakeSmtp, fakeSmtp } from "@mod/conformance/testing";
import { httpLedger, identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { secondFactorArea } from "../src/main.ts";
import { browser, issuer, password, running } from "../src/testing.ts";

const pair = generateKeyPairSync("ed25519");
const credential = randomBytes(32).toString("hex");
/** The address the ledger states for each user now; a scene changes it. */
const stated = new Map<string, string>();

describe.runIf(areaTarget().can(httpLedger))(
	"a code by mail for a user from a ledger whose address changed",
	() => {
		let smtp: FakeSmtp;
		let ledger: Fake;
		// Both started before the target, which reaches them.
		beforeAll(async () => {
			smtp = await fakeSmtp();
			ledger = await fakeHttp(async (asked) => {
				if (asked.headers.authorization !== `Bearer ${credential}`) return { status: 401 };
				if (asked.method !== "POST" || asked.path !== "/ledger/authenticate")
					return { status: 404 };
				const given = JSON.parse(asked.body);
				const email = stated.get(given.email);
				if (email === undefined) return { status: 401 };
				if (given.password !== password) return { status: 403 };
				return { json: { id: `s-${given.email}`, username: given.email, email } };
			});
		});
		afterAll(async () => {
			await smtp?.stop();
			await ledger?.stop();
		});
		const s = running(() =>
			sceneOf(
				keysArea.part({
					signing: {
						kid: "mfa-ledger",
						alg: "EdDSA",
						privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
						publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
					},
				}),
				identityArea.part({
					origin: issuer,
					users: [],
					ledger: { verifyUrl: `${ledger.base}/ledger/authenticate`, credential },
					login: { attempts: 100, windowSeconds: 600 },
				}),
				secondFactorArea.part({ mode: "optional", mail: { host: smtp.host, port: smtp.port } }),
			),
		);
		const codeTo = (to: string, shape: RegExp) =>
			shape.exec(smtp.latestTo(to)?.text ?? "")?.[1] ?? "";

		/** Binds the user's address by the code mailed there, then has the ledger state another. */
		const boundThenMoved = async (user: string) => {
			stated.set(user, `${user}@example.com`);
			const b = browser(() => s.at.base);
			expect((await b.login(user)).status).toBe(200);
			const begun = await b.send("POST", "/session/mfa/enrollment", { kind: "email" });
			const done = await b.send("POST", "/session/mfa/enrollment/complete", {
				transaction_id: String(begun.body.transaction),
				proof: codeTo(`${user}@example.com`, /\b([0-9A-Z]{16})\b/),
			});
			expect(done.status).toBe(200);
			stated.set(user, `${user}@elsewhere.example`);
		};
		/** The next login's challenge to the bound factor. */
		const challenged = async (user: string) => {
			const held = await s.held(user);
			const factor = (await held.b.factors(held.transaction)).find((f) => f.kind === "email");
			return held.b.send("POST", "/session/mfa/challenge", {
				transaction_id: held.transaction,
				factor_id: factor?.id ?? "",
			});
		};

		it("refuses the factor's challenge once a later login gives another address, sending nothing", async () => {
			await boundThenMoved("lee");
			const sent = smtp.received.length;
			const answer = await challenged("lee");
			expect([answer.status, answer.body.error]).toEqual([403, "mfa_factor_refused"]);
			expect(smtp.received.length).toBe(sent);
		});

		it.runIf(areaTarget().can(auditEvents.need))(
			"records the address no longer matching, with the factor's kind and the login's purpose",
			async () => {
				await boundThenMoved("liv");
				const { events } = await s.trail().during(() => challenged("liv"));
				expect(events.filter((e) => e.kind === "mfa.email_address_mismatch")).toEqual([
					expect.objectContaining({
						subject: "s-liv",
						attributes: expect.objectContaining({ kind: "email", purpose: "login" }),
					}),
				]);
			},
		);
	},
);
