#!/usr/bin/env node
/** Writes the generated references, configuration and audit events, into the workspace this package lies in. */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { auditReferenceFile, auditReferenceOf, declarationsIn } from "./audit-events.ts";
import { referenceFile, referenceOf, sectionsIn } from "./configuration.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..");
await mkdir(dirname(referenceFile(root)), { recursive: true });
await writeFile(referenceFile(root), referenceOf(await sectionsIn(root)));
await writeFile(auditReferenceFile(root), auditReferenceOf(await declarationsIn(root)));
