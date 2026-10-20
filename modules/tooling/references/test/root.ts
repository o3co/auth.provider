import { join } from "node:path";

/** The workspace whose references the tests hold to the committed files. */
export const root = join(import.meta.dirname, "..", "..", "..", "..");
