import { reportRun } from "../vitest.ts";

// A run whose every test passed, was excused, or waits for review, and whose driver ended well:
// each of its tests is reported, and none fails.
reportRun("a plan as the harness reports it", {
	modules: [
		{ testModule: "oidcc-server", variant: { a: "1" }, log: [], outcome: { kind: "passed" } },
		{
			testModule: "oidcc-scope-phone",
			variant: {},
			log: [],
			outcome: { kind: "excused", class: "optional" },
		},
		{ testModule: "oidcc-prompt-login", variant: {}, log: [], outcome: { kind: "review" } },
	],
	unused: [],
	strayNotRun: [],
	driver: { name: "the suite's own runner", code: 0, log: "runner.log" },
	artifacts: "/records/basic",
});
