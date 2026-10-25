// A fake adapter: each instruction's `script` says what it writes, line by line, and how it ends.
import { createInterface } from "node:readline";

const lines = createInterface({ input: process.stdin });
const write = (value: unknown) =>
	process.stdout.write(`${typeof value === "string" ? value : JSON.stringify(value)}\n`);
let script: unknown[] = [];
let step = 0;
const next = () => {
	if (step >= script.length) return;
	const at = script[step++];
	if (at === "exit") process.exit(4);
	if (at === "hang") return;
	if (at === "split") {
		// One line in two writes, parted inside a character, as a pipe may part it.
		const bytes = Buffer.from(`${JSON.stringify({ result: { name: "日本語" } })}\n`);
		const cut = bytes.indexOf(Buffer.from("本")) + 1;
		process.stderr.write(Buffer.from("ü").subarray(0, 1));
		process.stdout.write(bytes.subarray(0, cut));
		setTimeout(() => {
			process.stderr.write(Buffer.from("ü").subarray(1));
			process.stdout.write(bytes.subarray(cut));
		}, 50);
		return;
	}
	write(at);
	if (typeof at === "object" && at !== null && "ask" in at) return;
	next();
};
lines.on("line", (text) => {
	const value = JSON.parse(text);
	if (step === 0 && Array.isArray(value.script)) {
		script = value.script;
		process.stderr.write("the library speaks here\n");
		return next();
	}
	next();
});
