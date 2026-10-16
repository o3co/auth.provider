import { assemble, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { subjectRevocation } from "@mod/subject-revocation";
import revocationModule from "@mod/subject-revocation/module";
import revocationStore from "@mod/subject-revocation-store/module";
import { tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { beforeEach, expect, it } from "vitest";
import subjectTokens from "../src/module.ts";

const start = 1_800_000_000_000;
let now = start;
const runtime = quietRuntime({ clock: { now: () => now } });
beforeEach(() => {
	now = start;
});

/** Tokens checked by subject-tokens, over subject-revocation on a simulated store. */
async function boot() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [tokensStandIn(), revocationModule, revocationStore, simulated.module, subjectTokens],
		config: kernelConfig(),
		runtime,
	});
	const t = app.get(tokens);
	const issue = async (subject: string) => {
		const grant = { subject, issuedTo: "c", audience: ["api"], scope: [] };
		const issued = await t.issue({ grant, grantType: "test" });
		if (issued.kind !== "issued") throw new Error(issued.reason);
		return issued.access.token;
	};
	const revoke = (subject: string) => app.get(subjectRevocation).revoke(subject);
	return { t, issue, revoke, simulated };
}

it("fails a token issued up to its subject's revocation, and no other subject's", async () => {
	const s = await boot();
	const early = await s.issue("alice");
	const other = await s.issue("bob");
	await s.revoke("alice");
	expect(await s.t.verifyAccess(early)).toEqual({ kind: "invalid", reason: "revoked" });
	expect((await s.t.verifyAccess(other)).kind).toBe("valid");
});

it("keeps a token issued in a later second than the revocation", async () => {
	const s = await boot();
	await s.revoke("alice");
	now += 1000;
	expect((await s.t.verifyAccess(await s.issue("alice"))).kind).toBe("valid");
});

it("is unavailable, never valid or revoked, while the revocation cannot be read", async () => {
	const s = await boot();
	const token = await s.issue("alice");
	s.simulated.unreachable(true);
	await expect(s.t.verifyAccess(token)).rejects.toSatisfy(isUnavailable);
});
