#!/usr/bin/env node
/** Writes the generated references, configuration (with each package's defaults), audit events and routes, into the workspace this package lies in. */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { attackSurfaceFile, attackSurfaceIn, attackSurfaceOf } from "./attack-surface/surface.ts";
import { auditReferenceFile, auditReferenceOf, declarationsIn } from "./audit-events.ts";
import {
	clientSectionsOf,
	idpTypesOf,
	referenceConfFile,
	referenceConfOf,
	referenceFile,
	referenceOf,
	sectionsIn,
} from "./configuration.ts";
import { routesFile, routesIn, routesOf } from "./routes.ts";

const root = join(import.meta.dirname, "..", "..", "..", "..");
await mkdir(dirname(referenceFile(root)), { recursive: true });
const sections = await sectionsIn(root);
await writeFile(
	referenceFile(root),
	referenceOf(sections, await clientSectionsOf(root), await idpTypesOf(root)),
);
for (const s of sections) await writeFile(referenceConfFile(s.dir), referenceConfOf(s));
await writeFile(auditReferenceFile(root), auditReferenceOf(await declarationsIn(root)));
await writeFile(routesFile(root), routesOf(await routesIn(root)));
await writeFile(attackSurfaceFile(root), attackSurfaceOf(await attackSurfaceIn(root)));
