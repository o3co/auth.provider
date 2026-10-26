import { runPlan } from "../src/harness/harness.ts";
import { reportRun } from "../src/harness/report.ts";
import { plans } from "../src/plans.ts";

// The plan runs as the file is read, so that each suite test is a test of its own.
reportRun(plans["backchannel-logout"].suitePlan, await runPlan(plans["backchannel-logout"]));
