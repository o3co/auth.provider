import { changeRecords } from "@mod/records";
import { subjectWriter } from "@mod/store/subject-writer";

/**
 * `changeRecords` with the subject writer: every change subject-records makes goes through here. The
 * writer stays in this module and is handed to `records`' `changeRecords` alone.
 */
export const changeWritten = (p: Omit<Parameters<typeof changeRecords>[0], "writer">) =>
	changeRecords({ ...p, writer: subjectWriter });
