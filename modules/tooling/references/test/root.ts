import { join } from "node:path";
import { readWorkspace } from "@mod/guard-imports";

/** The workspace whose references the tests hold to the committed files. */
export const root = join(import.meta.dirname, "..", "..", "..", "..");
/** Its packages, read once, as the generator reads them. */
export const packages = readWorkspace(root);
