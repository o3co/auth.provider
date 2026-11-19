import type { ErasureJournal } from "@mod/erasure-journal";
import { type Clock, contract } from "@mod/kernel";
import { inFrame, type Kept } from "../frame/frame.ts";
import type { ErasureMaintenance } from "../maintenance/maintenance.ts";
import type { NotShownAlone } from "../step/step.ts";

/** A command's run as its `call` entry gives it: the lines it writes, and the code it exits with. */
export interface CommandRun {
	readonly lines: readonly string[];
	readonly code: number;
}

/** The erasure commands, each as its app entry calls it with the operator's arguments. */
export interface ErasureCommands {
	/** `erasure-enter`: enters the maintenance key, shown alone, writing the entry time. */
	enter(args: readonly string[]): Promise<CommandRun>;
}

export const erasureCommands = contract<ErasureCommands>("account-erasure.commands");

/** Each command's exit codes, fixed once; 1 and 78 are app-entries' own. */
export const commandCodes = Object.freeze({
	done: 0,
	accompanied: 2,
	unchecked: 3,
	enteredNotShownAlone: 4,
	busy: 5,
	notInMaintenance: 6,
	holdLeft: 7,
	usage: 64,
});

/** The line a command adds to its answer's own where its hold's release failed. */
const holdLeftLine =
	"the journal's hold may be left, as its release failed; release it once this process is gone, before the next erasure command";

/** A line an operator reads as written: no control, format or line-separator character. */
const unprintable = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const holderMax = 200;

/** The journal's holder as the medium records it, where it is one non-empty line of at most 200 characters with no control, format or line-separator character; none otherwise. */
const holderLine = (holder: string) =>
	holder.length > 0 && holder.length <= holderMax && !unprintable.test(holder) ? holder : undefined;

/** The holder for the operator: as recorded where it is one non-empty line of at most 200 characters with no control, format or line-separator character, or a fixed text. */
const holderOf = (holder: string) => {
	const line = holderLine(holder);
	return line === undefined ? "unreadable holder" : `holder: ${line}`;
};

const attached = (count: number) =>
	`${count} other ${count === 1 ? "process" : "processes"} attached`;

/** What the read after entering showed in place of `alone`, in the operator's words. */
const shown = (found: NotShownAlone) => {
	if (found.kind === "accompanied") return attached(found.count);
	if (found.kind === "unchecked")
		return `not every process could be seen: ${found.reasons.join(", ")}`;
	return "the store gave no answer";
};

/** The parts every command runs with. */
export interface CommandParts {
	readonly journal: ErasureJournal;
	readonly maintenance: ErasureMaintenance;
	readonly clock: Clock;
}

/** `erasure-enter`, in the frame: its answer as the lines and code its entry writes. */
export function enterCommand(parts: CommandParts): ErasureCommands["enter"] {
	return async (args) => {
		if (args.length > 0) {
			return { lines: ["usage: erasure-enter (it takes no arguments)"], code: commandCodes.usage };
		}
		const answer = await inFrame(parts, "entering", async (epoch) => ({
			kind: "entered" as const,
			epoch,
		}));
		if (answer.kind !== "hold-left") return enterRun(answer);
		return {
			lines: [...enterRun(answer.answer).lines, holdLeftLine],
			code: commandCodes.holdLeft,
		};
	};
}

/** `erasure-enter`'s answer, apart from `hold-left`, as the lines and code its entry writes. */
function enterRun(answer: Kept | { readonly kind: "entered"; readonly epoch: string }): CommandRun {
	switch (answer.kind) {
		case "entered":
			return {
				lines: [`entered maintenance under epoch ${answer.epoch}; this process was shown alone`],
				code: commandCodes.done,
			};
		case "accompanied":
			return {
				lines: [`not entered: ${attached(answer.count)}; stop them, then run erasure-enter again`],
				code: commandCodes.accompanied,
			};
		case "unchecked":
			return {
				lines: [
					`not entered: not every process could be seen (${answer.reasons.join(", ")}); run erasure-enter again once every server answers`,
				],
				code: commandCodes.unchecked,
			};
		case "entered-not-shown-alone":
			return {
				lines: [
					`entered maintenance under epoch ${answer.epoch}, but this process was not shown alone (${shown(answer.found)}); the key stays set; ${answer.wayOn}`,
				],
				code: commandCodes.enteredNotShownAlone,
			};
		case "busy":
			return {
				lines: [
					`not run: the journal is held (${holderOf(answer.holder)}); run erasure-enter again once its holder ends, or release the hold once its process is gone`,
				],
				code: commandCodes.busy,
			};
		case "not-in-maintenance":
			return {
				lines: ["not run: the maintenance key is not held"],
				code: commandCodes.notInMaintenance,
			};
	}
}
