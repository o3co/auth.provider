import { type RunnerTestCase, type RunnerTestSuite, TestRunner } from "vitest";

type Task = RunnerTestCase | RunnerTestSuite;

/** The innermost suite whose `beforeAll` is running, if any. */
function starting(tasks: readonly Task[]): RunnerTestSuite | undefined {
	for (const task of tasks) {
		if (task.type !== "suite" || task.result?.state !== "run") continue;
		const inner = starting(task.tasks);
		if (inner) return inner;
		if (task.result.hooks?.beforeAll === "run") return task;
	}
	return undefined;
}

function firstTest(tasks: readonly Task[]): RunnerTestCase | undefined {
	for (const task of tasks) {
		const found = task.type === "test" ? task : firstTest(task.tasks);
		if (found) return found;
	}
	return undefined;
}

/** Skips the running test with the reason; from a suite's `beforeAll`, every test of that suite. */
export function leaveOut(reason: string): never {
	const running = TestRunner.getCurrentTest<RunnerTestCase | undefined>();
	if (running) running.context.skip(reason);
	const file = TestRunner.getCurrentSuite().file;
	const suite =
		starting(file.tasks) ?? (file.result?.hooks?.beforeAll === "run" ? file : undefined);
	firstTest(suite?.tasks ?? [])?.context.skip(reason);
	throw new Error(`${reason}: left out outside a test or a suite's beforeAll`);
}
