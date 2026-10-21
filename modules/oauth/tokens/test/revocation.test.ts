import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import senderBindingModule from "@mod/sender-binding/module";
import { denylistAllowanceMs } from "@mod/token-denylist";
import { beforeEach, expect, it } from "vitest";
import {
	type AccessGrant,
	type IssueLimits,
	referenceOf,
	type Tokens,
	tokens,
} from "../src/contract.ts";
import tokensModule from "../src/module.ts";
import { tokensConfig } from "../src/testing.ts";
import { revokedInMemory } from "./revoked.ts";

const start = 1_800_000_000_000;
let now = start;
beforeEach(() => {
	now = start;
});
const lifetimeMs = 3_600_000;
/** Moves the kernel's clock to this long after `boot` issued its tokens. */
const after = (ms: number) => {
	now = start + ms;
};
const runtime = quietRuntime({ clock: { now: () => now } });
const grant = { subject: "s", issuedTo: "c", audience: ["api"], scope: [] };

/** Issues through `issue`, which nothing here refuses, and answers what it issued. */
async function issueFor(t: Tokens, grant: AccessGrant, limits?: IssueLimits) {
	const issued = await t.issue({ grant, grantType: "test" }, limits);
	if (issued.kind !== "issued") throw new Error(`refused by ${issued.policy}`);
	return issued.access;
}

/** Tokens over revoked tokens kept in memory, on a place clock that may run apart from ours. */
async function boot() {
	const { module: revoked, place } = revokedInMemory(() => now);
	const app = await assemble({
		modules: [http, keysModule, issuerModule, senderBindingModule, tokensModule, revoked],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...keysConfig(),
			...issuerConfig(),
			...tokensConfig({ revocation: "denylist", "access-token-lifetime": "1h" }),
		},
		runtime,
	});
	const t = app.get(tokens);
	return { place, t, token: (await issueFor(t, grant)).token };
}

it("keeps refusing until the token expires while the place's clock runs ahead", async () => {
	const { place, t, token } = await boot();
	place.shift = 200_000;
	expect(await t.revokeAccess(token)).toEqual({ kind: "revoked" });
	after(lifetimeMs - 1_000);
	expect(await t.verifyAccess(token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("revokes by reference from the kernel's clock alone, and refuses while the place's clock runs ahead", async () => {
	const { place, t } = await boot();
	const issued = await issueFor(t, grant);
	place.shift = 200_000;
	expect(await t.revokeReferenced(referenceOf(issued))).toEqual({ kind: "revoked" });
	after(lifetimeMs - 1_000);
	expect(await t.verifyAccess(issued.token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("revokes a token just expired within the allowance, for hosts whose clocks are behind", async () => {
	const { t, token } = await boot();
	after(lifetimeMs + 30_000);
	expect(await t.issuedToOf(token)).toEqual({ kind: "issued", issuedTo: "c" });
	expect(await t.revokeAccess(token)).toEqual({ kind: "revoked" });
	after(lifetimeMs - 1_000);
	expect(await t.verifyAccess(token)).toEqual({ kind: "invalid", reason: "revoked" });
	after(lifetimeMs + denylistAllowanceMs);
	expect(await t.issuedToOf(token)).toEqual({ kind: "invalid" });
	expect(await t.revokeAccess(token)).toEqual({ kind: "invalid" });
});

it("tells who a revoked token was issued to", async () => {
	const { t, token } = await boot();
	await t.revokeAccess(token);
	expect(await t.issuedToOf(token)).toEqual({ kind: "issued", issuedTo: "c" });
	expect(await t.issuedToOf("garbage")).toEqual({ kind: "invalid" });
});

it("revokes an issued token by its reference, without the token itself, and nothing by a string that is not one", async () => {
	const { t } = await boot();
	const issued = await issueFor(t, grant);
	expect(issued.expiresAt).toBe(start + lifetimeMs);
	expect(t.revocable()).toBe(true);
	expect(await t.revokeReferenced(referenceOf(issued))).toEqual({ kind: "revoked" });
	expect(await t.verifyAccess(issued.token)).toEqual({ kind: "invalid", reason: "revoked" });
	// Revocable until exactly its expiry plus the allowance.
	const edge = start - denylistAllowanceMs;
	expect(await t.revokeReferenced(referenceOf({ id: "ended", expiresAt: edge }))).toEqual({
		kind: "invalid",
	});
	expect(await t.revokeReferenced(referenceOf({ id: "ending", expiresAt: edge + 1 }))).toEqual({
		kind: "revoked",
	});
	expect(await t.revokeReferenced("not a reference")).toEqual({ kind: "invalid" });
});

it("judges whether an issued token can still be revoked by the kernel's clock, whatever the place's says", async () => {
	const { place, t } = await boot();
	const issued = await issueFor(t, grant);
	after(lifetimeMs + denylistAllowanceMs - 1_000);
	expect(await t.revokeReferenced(referenceOf(issued))).toEqual({ kind: "revoked" });
	after(lifetimeMs + denylistAllowanceMs + 1_000);
	place.shift = -120_000;
	expect(await t.revokeReferenced(referenceOf(issued))).toEqual({ kind: "invalid" });
});

it("keeps refusing when the place's clock runs ahead after the revocation, within the allowance", async () => {
	const { place, t, token } = await boot();
	expect(await t.revokeAccess(token)).toEqual({ kind: "revoked" });
	// As after a failover to a host whose clock is ahead.
	place.shift = 50_000;
	after(lifetimeMs - 1_000);
	expect(await t.verifyAccess(token)).toEqual({ kind: "invalid", reason: "revoked" });
});

it("answers unavailable, never valid or invalid, while the revoked tokens' place does not answer", async () => {
	const { place, t, token } = await boot();
	const issued = await issueFor(t, grant);
	place.down = true;
	await expect(t.verifyAccess(token)).rejects.toBeInstanceOf(Unavailable);
	await expect(t.revokeAccess(token)).rejects.toBeInstanceOf(Unavailable);
	await expect(t.revokeReferenced(referenceOf(issued))).rejects.toBeInstanceOf(Unavailable);
	place.down = false;
	expect(await t.verifyAccess(token)).toMatchObject({ kind: "valid" });
});
