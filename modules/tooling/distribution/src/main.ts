import { check, readBundles } from "./contract.ts";

const problems = check(readBundles(process.env.INIT_CWD ?? process.cwd()));
for (const problem of problems) process.stdout.write(`${problem}\n`);
process.stdout.write(
	problems.length === 0 ? "distribution: ok\n" : `distribution: ${problems.length}\n`,
);
process.exit(problems.length === 0 ? 0 : 1);
