import { expect, it } from "vitest";
import { harness } from "../../../test/harness.ts";

it("warns at every start that keeps established grants at a subject's revocation", async () => {
	const warned = async (settings: Record<string, unknown>) =>
		(await harness({ settings }))
			.logs()
			.filter((line) => line.event === "federation-grants.kept_on_subject_revocation");
	expect(await warned({ "keep-on-subject-revocation": true })).toEqual([
		{
			level: "warn",
			event: "federation-grants.kept_on_subject_revocation",
			fields: {
				reason: "an established grant answers only to the delegations boundary of a revocation",
			},
		},
	]);
	expect(await warned({})).toEqual([]);
});
