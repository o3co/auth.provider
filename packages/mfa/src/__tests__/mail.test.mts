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

/**
 * MFA mail (the MFA ADR's D5, F5 and D23, as #810 amended them): the one
 * place a code the provider issued is handed to the mail sender, and the
 * masked address a page may show. For a login code the account's address is
 * compared with the digest the factor recorded before anything is written;
 * then the pending state is kept with the digest of the address the code
 * goes to; then the sender is handed what the mail means, and what it
 * answered is read through `mailSendOutcome` alone.
 */

import { randomBytes } from "node:crypto";
import type { MailSender, MfaKeyedDigest } from "@o3co/auth-provider-core";
import { createRecordingMailSender } from "@o3co/auth-provider-core/testing";
import { describe, expect, it, vi } from "vitest";
import { maskMailAddress, sendMfaMail } from "#/mail.mjs";
import { createMfaSealing } from "#/sealing.mjs";

const NOW = 1_900_000_000_000;
const NOT_AFTER = NOW + 600_000;
const ADDRESS = "Alice@Example.COM";
const NORMALISED = "alice@example.com";

const sealing = createMfaSealing({ ring: [{ id: "k1", key: randomBytes(32) }] });
const digests = sealing.digestsFor("mailed");

/** A keep that records what it was handed and answers kept, with a clear that records itself. */
function keeping() {
	const kept: { addressDigest: MfaKeyedDigest; expiresAtMs: number }[] = [];
	const clear = vi.fn(async () => {});
	const keep = vi.fn(async (addressDigest: MfaKeyedDigest, expiresAtMs: number) => {
		kept.push({ addressDigest, expiresAtMs });
		return { kept: true as const, clear };
	});
	return { kept, keep, clear };
}

const loginCode = (addressDigest: unknown, extra: Record<string, unknown> = {}) => ({
	purpose: "login_code",
	code: "123456",
	expiresAtMs: NOW + 300_000,
	addressDigest,
	...extra,
});

const send = (
	options: {
		readonly sender?: MailSender | undefined;
		readonly mail?: unknown;
		readonly purpose?: "login_code" | "email_factor_enrollment" | "account_email_proof";
		readonly address?: unknown;
		readonly keep?: (
			addressDigest: MfaKeyedDigest,
			expiresAtMs: number,
		) => Promise<
			| { readonly kept: true; readonly clear: () => Promise<void> }
			| { readonly kept: false; readonly refusal: unknown }
		>;
	} = {},
) =>
	sendMfaMail({
		sender: "sender" in options ? options.sender : createRecordingMailSender(),
		mail: options.mail ?? loginCode(digests.digest([NORMALISED])),
		purpose: options.purpose ?? "login_code",
		subject: "u-alice",
		address: "address" in options ? options.address : ADDRESS,
		nowMs: NOW,
		notAfterMs: NOT_AFTER,
		digests,
		keep: options.keep ?? keeping().keep,
	});

describe("sendMfaMail — a login code", () => {
	it("keeps the state with the digest of the address it goes to, then hands the sender what the mail means, and answers sent", async () => {
		const sender = createRecordingMailSender();
		const { kept, keep } = keeping();
		const outcome = await send({ sender, keep });
		expect(outcome).toEqual({ outcome: "sent", to: NORMALISED, expiresAtMs: NOW + 300_000 });
		expect(kept).toEqual([
			{ addressDigest: digests.digest([NORMALISED]), expiresAtMs: NOW + 300_000 },
		]);
		expect(sender.sent).toEqual([
			{
				purpose: "login_code",
				subject: "u-alice",
				to: NORMALISED,
				code: "123456",
				expiresAtMs: NOW + 300_000,
			},
		]);
	});

	it("compares the address before anything is written: another address's digest is a mismatch — nothing kept, nothing sent", async () => {
		const sender = createRecordingMailSender();
		const { keep } = keeping();
		const outcome = await send({
			sender,
			keep,
			mail: loginCode(digests.digest(["bob@example.com"])),
		});
		expect(outcome).toEqual({ outcome: "address_mismatch" });
		expect(keep).not.toHaveBeenCalled();
		expect(sender.sent).toEqual([]);
	});

	it("reads a digest that is null, or no keyed digest, as a mismatch — never throws, never sends", async () => {
		for (const addressDigest of [
			null,
			undefined,
			{},
			"digest",
			{ keyId: 1, digest: "x" },
			{ keyId: "k1", digest: 5 },
			{ keyId: "k1", digest: "not-a-digest" },
		]) {
			const sender = createRecordingMailSender();
			const { keep } = keeping();
			const outcome = await send({ sender, keep, mail: loginCode(addressDigest) });
			expect(outcome, JSON.stringify(addressDigest)).toEqual({ outcome: "address_mismatch" });
			expect(keep).not.toHaveBeenCalled();
			expect(sender.sent).toEqual([]);
		}
	});

	it("reads an account with no address, or one that is no address, as a mismatch", async () => {
		for (const address of [undefined, "", "not an address", "a@b, c@d"]) {
			const { keep } = keeping();
			expect(await send({ keep, address }), JSON.stringify(address)).toEqual({
				outcome: "address_mismatch",
			});
			expect(keep).not.toHaveBeenCalled();
		}
	});

	it("answers a digest under a key the ring no longer holds as the key's outage: nothing kept, nothing sent", async () => {
		const sender = createRecordingMailSender();
		const { keep } = keeping();
		const stored = digests.digest([NORMALISED]);
		const outcome = await send({ sender, keep, mail: loginCode({ ...stored, keyId: "gone" }) });
		expect(outcome).toEqual({ outcome: "key_unavailable", keyId: "gone" });
		expect(keep).not.toHaveBeenCalled();
		expect(sender.sent).toEqual([]);
	});
});

describe("sendMfaMail — what the sender answered", () => {
	it("answers a limit refused_at_limit, and clears the pending state", async () => {
		const sender = createRecordingMailSender();
		sender.refuseAtLimit();
		const { keep, clear } = keeping();
		expect(await send({ sender, keep })).toEqual({ outcome: "refused_at_limit", cleared: true });
		expect(clear).toHaveBeenCalledTimes(1);
	});

	it("answers a rejection as an outage, with its cause, and clears the pending state", async () => {
		const sender = createRecordingMailSender();
		const down = new Error("relay down");
		sender.failWith(down);
		const { keep, clear } = keeping();
		expect(await send({ sender, keep })).toEqual({
			outcome: "unavailable",
			cause: down,
			cleared: true,
		});
		expect(clear).toHaveBeenCalledTimes(1);
	});

	it("reads what the sender resolved with through mailSendOutcome alone: any other answer is an outage, never sent", async () => {
		for (const answer of [
			undefined,
			{ outcome: "delivered", extra: true },
			{ outcome: "queued" },
			Object.defineProperty({}, "outcome", { get: () => "delivered", enumerable: true }),
		]) {
			const sender: MailSender = { kind: "odd", send: async () => answer as never };
			const { keep, clear } = keeping();
			const outcome = await send({ sender, keep });
			expect(outcome.outcome, JSON.stringify(answer)).toBe("unavailable");
			expect(clear).toHaveBeenCalledTimes(1);
		}
	});

	it("says whether the pending state was cleared: a clear that fails leaves cleared false", async () => {
		const sender = createRecordingMailSender();
		sender.refuseAtLimit();
		const keep = async () => ({
			kept: true as const,
			clear: async () => {
				throw new Error("store down");
			},
		});
		expect(await send({ sender, keep: vi.fn(keep) })).toEqual({
			outcome: "refused_at_limit",
			cleared: false,
		});
	});
});

describe("sendMfaMail — before anything is written", () => {
	it("answers no sender without comparing, keeping or sending", async () => {
		const { keep } = keeping();
		expect(await send({ sender: undefined, keep })).toEqual({ outcome: "no_sender" });
		expect(keep).not.toHaveBeenCalled();
	});

	it("answers what keep refused with, and sends nothing", async () => {
		const sender = createRecordingMailSender();
		const keep = vi.fn(async () => ({ kept: false as const, refusal: "gone" }));
		expect(await send({ sender, keep })).toEqual({ outcome: "not_kept", refusal: "gone" });
		expect(sender.sent).toEqual([]);
	});

	it("refuses a mail of another purpose than the call's, without a code, or expiring by now, as malformed", async () => {
		for (const mail of [
			{ ...loginCode(digests.digest([NORMALISED])), purpose: "email_factor_enrollment" },
			loginCode(digests.digest([NORMALISED]), { code: "" }),
			loginCode(digests.digest([NORMALISED]), { code: 123456 }),
			loginCode(digests.digest([NORMALISED]), { expiresAtMs: NOW }),
			loginCode(digests.digest([NORMALISED]), { expiresAtMs: "later" }),
			null,
			"123456",
		]) {
			const { keep } = keeping();
			expect(await send({ keep, mail }), JSON.stringify(mail)).toEqual({ outcome: "malformed" });
			expect(keep).not.toHaveBeenCalled();
		}
	});

	it("keeps and sends a code until the transaction's expiry at the latest", async () => {
		const sender = createRecordingMailSender();
		const { kept, keep } = keeping();
		const later = loginCode(digests.digest([NORMALISED]), { expiresAtMs: NOT_AFTER + 60_000 });
		expect(await send({ sender, keep, mail: later })).toMatchObject({ expiresAtMs: NOT_AFTER });
		const unset = loginCode(digests.digest([NORMALISED]), { expiresAtMs: undefined });
		expect(await send({ sender, keep, mail: unset })).toMatchObject({ expiresAtMs: NOT_AFTER });
		expect(kept.map((entry) => entry.expiresAtMs)).toEqual([NOT_AFTER, NOT_AFTER]);
		expect(sender.sent.map((mail) => mail.expiresAtMs)).toEqual([NOT_AFTER, NOT_AFTER]);
	});
});

describe("sendMfaMail — a code that stands in for a factor", () => {
	for (const purpose of ["email_factor_enrollment", "account_email_proof"] as const) {
		it(`sends ${purpose} to the account's address with nothing to compare`, async () => {
			const sender = createRecordingMailSender();
			const { kept, keep } = keeping();
			const outcome = await send({
				sender,
				keep,
				purpose,
				mail: { purpose, code: "0123456789ABCDEF" },
			});
			expect(outcome).toEqual({ outcome: "sent", to: NORMALISED, expiresAtMs: NOT_AFTER });
			expect(kept).toEqual([
				{ addressDigest: digests.digest([NORMALISED]), expiresAtMs: NOT_AFTER },
			]);
			expect(sender.sent).toEqual([
				{ purpose, subject: "u-alice", to: NORMALISED, code: "0123456789ABCDEF", expiresAtMs: NOT_AFTER },
			]);
		});

		it(`answers ${purpose} to an account with no address no_address, keeping nothing`, async () => {
			const { keep } = keeping();
			expect(
				await send({ keep, purpose, address: undefined, mail: { purpose, code: "0123456789ABCDEF" } }),
			).toEqual({ outcome: "no_address" });
			expect(keep).not.toHaveBeenCalled();
		});
	}
});

describe("maskMailAddress", () => {
	it("shows the first character of the local part and the domain, as the provider spells the address", () => {
		expect(maskMailAddress("kate@example.com")).toBe("k***@example.com");
		expect(maskMailAddress("  Kate@Example.COM ")).toBe("k***@example.com");
		expect(maskMailAddress("a@example.com")).toBe("a***@example.com");
		expect(maskMailAddress("ünal@bücher.example")).toBe("ü***@xn--bcher-kva.example");
		expect(maskMailAddress('"kate.doe"@example.com')).toBe("k***@example.com");
	});

	it("answers nothing for a value that is no address", () => {
		for (const value of [undefined, null, "", "kate", "a@b, c@d", 5]) {
			expect(maskMailAddress(value), JSON.stringify(value)).toBeUndefined();
		}
	});
});
