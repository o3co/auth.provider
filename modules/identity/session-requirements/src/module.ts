import { defineModule } from "@mod/kernel";
import { entryJudge } from "@mod/session";
import { entryRequirements } from "./contract.ts";
import { judgeOf } from "./judge.ts";

export default defineModule(
	{ name: "session-requirements", replicaSafe: true, takes: [entryRequirements] },
	(m) => [m.contribute(entryJudge).by(async (c) => judgeOf(await c.collect(entryRequirements)))],
);
