import { changeRecords } from "@mod/records";
import { subjectWriter } from "@mod/store/subject-writer";

/**
 * `changeRecords` with the subject writer: every change subject-records makes goes through here, so
 * the store takes it as subject-records' own. The writer stays in this module: nothing exports it.
 */
export const changeWritten = (p: Omit<Parameters<typeof changeRecords>[0], "writer">) =>
	changeRecords({ ...p, writer: subjectWriter });
