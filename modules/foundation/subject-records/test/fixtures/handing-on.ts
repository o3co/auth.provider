/** A module that hands the subject writer on, for the walk in writer.test.ts to find. */
import { subjectWriter } from "@mod/store/subject-writer";

export const direct = subjectWriter;
export const nested = { deep: [{ held: subjectWriter }] };
export class Holder {
	static kept = subjectWriter;
}
