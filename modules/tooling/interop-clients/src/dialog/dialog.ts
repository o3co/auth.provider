import { spawn } from "node:child_process";

/** How an adapter is started: a program on the path, its arguments, where and with what. */
export interface AdapterCommand {
	readonly command: string;
	readonly args: readonly string[];
	readonly cwd: string;
	readonly env: Readonly<Record<string, string>>;
}

/** A question an adapter puts mid-flow, such as a URL a browser must visit; `ask` names its kind. */
export interface Ask {
	readonly ask: string;
	readonly [field: string]: unknown;
}

/** How a flow ended: the adapter's result, or why it did not give one. */
export type Outcome =
	| { readonly kind: "result"; readonly result: Readonly<Record<string, unknown>> }
	| { readonly kind: "error"; readonly type: string; readonly message: string };

/** One line of the dialog, as it was sent: `in` to the adapter, `out` from it. */
export interface Line {
	readonly to: "in" | "out";
	readonly text: string;
}

export interface Dialog {
	readonly outcome: Outcome;
	readonly transcript: readonly Line[];
	/** What the adapter wrote on its error stream, its library's own words. */
	readonly stderr: string;
}

const isObject = (v: unknown): v is Record<string, unknown> =>
	typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Runs one flow with an adapter: the instruction goes in as one JSON line; each line the adapter
 * writes is an ask, answered as one JSON line, or its result or its error, which end the flow.
 * Anything else, an exit before the end, or the time running out ends it as a protocol error.
 */
export function converse(
	adapter: AdapterCommand,
	instruction: Readonly<Record<string, unknown>>,
	answer: (ask: Ask) => Promise<Readonly<Record<string, unknown>>>,
	timeoutMs: number,
): Promise<Dialog> {
	const child = spawn(adapter.command, [...adapter.args], {
		cwd: adapter.cwd,
		env: { ...adapter.env },
		stdio: ["pipe", "pipe", "pipe"],
	});
	const transcript: Line[] = [];
	let stderr = "";
	let pending = "";
	let ended: Outcome | undefined;
	return new Promise<Dialog>((resolve) => {
		const end = (outcome: Outcome) => {
			if (ended) return;
			ended = outcome;
			clearTimeout(timer);
			child.stdin.end();
			if (child.exitCode === null) child.kill("SIGTERM");
			resolve({ outcome, transcript, stderr });
		};
		const protocol = (message: string) => end({ kind: "error", type: "protocol", message });
		const send = (value: unknown) => {
			const text = JSON.stringify(value);
			transcript.push({ to: "in", text });
			child.stdin.write(`${text}\n`);
		};
		const timer = setTimeout(() => protocol(`no result in ${timeoutMs}ms`), timeoutMs);
		const take = (text: string) => {
			// What follows the end is no part of the flow.
			if (ended) return;
			transcript.push({ to: "out", text });
			let line: unknown;
			try {
				line = JSON.parse(text);
			} catch {
				return protocol(`not a JSON line: ${text.slice(0, 200)}`);
			}
			if (!isObject(line)) return protocol(`not a JSON object: ${text.slice(0, 200)}`);
			if (isObject(line.result)) return end({ kind: "result", result: line.result });
			if (isObject(line.error))
				return end({
					kind: "error",
					type: String(line.error.type ?? "adapter"),
					message: String(line.error.message ?? ""),
				});
			if (typeof line.ask === "string")
				return void answer(line as Ask).then(send, (error: unknown) =>
					protocol(`the answer to ${line.ask} failed: ${String(error)}`),
				);
			protocol(`neither an ask, a result nor an error: ${text.slice(0, 200)}`);
		};
		child.stdout.on("data", (chunk: Buffer) => {
			pending += chunk;
			for (let at = pending.indexOf("\n"); at >= 0; at = pending.indexOf("\n")) {
				const text = pending.slice(0, at).trim();
				pending = pending.slice(at + 1);
				if (text !== "") take(text);
			}
		});
		child.stderr.on("data", (chunk: Buffer) => {
			stderr += chunk;
		});
		child.on("error", (error) => protocol(`could not start: ${error.message}`));
		child.on("exit", (code, signal) =>
			protocol(`exited (${signal ?? code}) before a result: ${stderr.slice(-500)}`),
		);
		child.stdin.on("error", () => {});
		send(instruction);
	});
}
