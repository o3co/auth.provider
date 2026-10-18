#!/usr/bin/env node
/** Writes the generated references, configuration (with each package's defaults) and audit events, into the workspace this package lies in. */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { auditReferenceFile, auditReferenceOf, declarationsIn } from "./audit-events.ts";
import {
	referenceConfFile,
	referenceConfOf,
	referenceFile,
	referenceOf,
	sectionsIn,
} from "./configuration.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..", "..");
await mkdir(dirname(referenceFile(root)), { recursive: true });
const sections = await sectionsIn(root);
await writeFile(referenceFile(root), referenceOf(sections));
for (const s of sections) await writeFile(referenceConfFile(s.dir), referenceConfOf(s));
await writeFile(auditReferenceFile(root), auditReferenceOf(await declarationsIn(root)));
