import { changeRecords } from "@mod/records";
import { subjectWriter } from "@mod/store/subject-writer";

/**
 * `changeRecords` with the subject writer: every change subject-records makes goes through here. The
 * writer stays in this module and is never handed to another package.
 */
export const changeWritten = (p: Omit<Parameters<typeof changeRecords>[0], "writer">) =>
	changeRecords({ ...p, writer: subjectWriter });
