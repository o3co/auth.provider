import { erasureMarks } from "@mod/erasure-extensions";
import { assemble, contract, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { subjectErasure, subjectRevocation } from "@mod/subject-revocation";
import revocationModule from "@mod/subject-revocation/module";
import revocationStore from "@mod/subject-revocation-store/module";
import { type IssuanceFence, issuanceFences, tokens } from "@mod/tokens";
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
const assembly = () => {
	const simulated = simulatedStore();
	const input = {
		modules: [tokensStandIn(), revocationModule, revocationStore, simulated.module, subjectTokens],
		config: kernelConfig(),
		runtime,
	};
	return { input, simulated };
};

async function boot() {
	const { input, simulated } = assembly();
	const app = await assemble(input);
	const t = app.get(tokens);
	const issue = async (subject: string, standingAt?: number) => {
		const grant = {
			subject,
			issuedTo: "c",
			audience: ["api"],
			scope: [],
			...(standingAt === undefined ? {} : { standingAt }),
		};
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

it("keeps a token issued in a later second than the revocation's boundary, its write's deadline", async () => {
	const s = await boot();
	await s.revoke("alice");
	// The boundary is the deadline its write was sent with, records' 10 s past the store's time.
	now += 11_000;
	expect((await s.t.verifyAccess(await s.issue("alice"))).kind).toBe("valid");
});

it("fails a token standing before its subject's revocation, though issued in a later second than it [guarantee-4-a]", async () => {
	const s = await boot();
	const checkedAt = now;
	await s.revoke("alice");
	now += 1000;
	expect(await s.t.verifyAccess(await s.issue("alice", checkedAt))).toEqual({
		kind: "invalid",
		reason: "revoked",
	});
});

it("is unavailable, never valid or revoked, while the revocation cannot be read", async () => {
	const s = await boot();
	const token = await s.issue("alice");
	s.simulated.unreachable(true);
	await expect(s.t.verifyAccess(token)).rejects.toSatisfy(isUnavailable);
});

it("takes all its module names", async () => {
	// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
	expect((await takesUnused(assembly().input))["subject-tokens"]).toBeUndefined();
});

it("fences a bundle for its subject: refused once the subject is erased, and lets an erasing composition start", async () => {
	const simulated = simulatedStore();
	simulated.mark(erasureMarks.enabled, true);
	const fenced = contract<readonly IssuanceFence[]>("test.fences");
	const app = await assemble({
		modules: [
			tokensStandIn(),
			revocationModule,
			revocationStore,
			simulated.module,
			subjectTokens,
			defineModule({ name: "fences", replicaSafe: false, takes: [issuanceFences] }, (m) => [
				m.provide(fenced).by((c) => c.collect(issuanceFences)),
			]),
		],
		config: kernelConfig(),
		runtime,
	});
	const [fence] = app.get(fenced);
	expect(fence?.name).toBe("subject-tokens");
	expect(await fence?.fence({ subject: "alice", receiptId: "r1" })).toBe("passed");
	await app.get(subjectErasure).markErased("alice");
	expect(await fence?.fence({ subject: "alice", receiptId: "r2" })).toBe("refused");
	expect(await fence?.fence({ subject: "bob", receiptId: "r3" })).toBe("passed");
});
