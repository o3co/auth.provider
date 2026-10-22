import { assemble, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type FactorManaging, factorManaging } from "@mod/mfa-managing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { expect, it } from "vitest";
import bridge from "../src/module.ts";

const runtime = quietRuntime();

/** mfa's decisions as far as the bridge asks them: each fence moved, or one that cannot be. */
const fencing = (fence: FactorManaging["fence"]) =>
	defineModule({ name: "factors-stand-in" }, (m) => [
		m.provide(factorManaging).by(() => ({ fence }) as FactorManaging),
	]);

const boot = (fence: FactorManaging["fence"]) =>
	assemble({
		modules: [subjectRevocationStandIn, fencing(fence), bridge],
		config: kernelConfig(),
		runtime,
	});

it("moves the subject's fence before a revocation is complete", async () => {
	const fenced: string[] = [];
	const app = await boot(async (subject) => {
		fenced.push(subject);
	});
	expect(await app.get(revocations).record("ann")).toEqual({ complete: true });
	expect(fenced).toEqual(["ann"]);
});

it("leaves a revocation incomplete while the fence cannot be moved", async () => {
	const app = await boot(async () => {
		throw new Unavailable("mfa");
	});
	expect(await app.get(revocations).record("bob")).toEqual({ complete: false });
});
