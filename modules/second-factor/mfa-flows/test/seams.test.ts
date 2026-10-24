import { jsonAnswer } from "@mod/http";
import { BootRefused, contract, defineModule } from "@mod/kernel";
import { takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { type EnrollmentFlow, enrollmentFlow, type FlowParts, flowParts } from "../src/contract.ts";
import { serve } from "./harness.ts";

it("hands the enrollment routes and an enrollment's challenge to the flow contributed", async () => {
	const seen: string[] = [];
	const flow: EnrollmentFlow = {
		enroll: async () => {
			seen.push("enroll");
			return jsonAnswer(200, { by: "flow" });
		},
		complete: async () => {
			seen.push("complete");
			return jsonAnswer(200, { by: "flow" });
		},
		challenge: async () => jsonAnswer(200, { by: "flow" }),
	};
	const contributing = defineModule({ name: "enrolling", takes: [] }, (m) => [
		m.contribute(enrollmentFlow).by(() => flow),
	]);
	const s = await serve({}, [contributing], null);
	await s.signIn("ada");
	expect((await s.call("POST", "/session/mfa/enrollment", { kind: "code" })).body).toEqual({
		by: "flow",
	});
	expect((await s.call("POST", "/session/mfa/enrollment/complete", {})).body).toEqual({
		by: "flow",
	});
	expect(seen).toEqual(["enroll", "complete"]);
});

it("offers its parts for the module binding factors: transactions, resume, recording, answers, requests, and the lockout", async () => {
	const parts = contract<FlowParts>("test.parts");
	const reading = defineModule({ name: "reading", takes: [flowParts] }, (m) => [
		m.provide(parts).by((c) => c.get(flowParts)),
	]);
	const s = await serve({}, [reading]);
	const got = s.app.get(parts);
	expect(Object.keys(got).sort()).toEqual([
		"answers",
		"askedFrom",
		"lockout",
		"record",
		"requests",
		"resume",
		"resumeWith",
		"transactions",
	]);
	expect(got.answers.loginRequired.status).toBe(401);
	expect(got.lockout.name).toBe("mfa");
	expect(got.lockout.policy.budget).toBe(10);
});

it("refuses to boot where no module binding factors contributes the enrollment flow", async () => {
	const refused = await serve({}, [], null).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals.map((r) => r.where)).toContain(
		"mfa-flows.enrollment-flow",
	);
});

it("takes all it names", async () => {
	expect(await takesUnused((await serve()).input)).toEqual({});
});
