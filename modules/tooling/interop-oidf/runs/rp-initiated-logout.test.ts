import { runPlan, titleOf } from "../src/harness/harness.ts";
import { plans } from "../src/plans.ts";
import { reportRun } from "../src/report/vitest.ts";

// The plan runs as the file is read, so that each suite test is a test of its own.
reportRun(titleOf(plans["rp-initiated-logout"]), await runPlan(plans["rp-initiated-logout"]));
