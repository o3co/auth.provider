#!/usr/bin/env node
/** Writes the generated references, configuration (with each package's defaults), audit events, routes, the attack surface and the audit index's cards and dependencies, into the workspace this package lies in. */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { readWorkspace } from "@mod/guard-imports";
import { attackSurfaceFile, attackSurfaceIn, attackSurfaceOf } from "./attack-surface/surface.ts";
import { auditReferenceFile, auditReferenceOf, declarationsIn } from "./audit-events.ts";
import {
	auditIndexIn,
	cardsFile,
	cardsOf,
	dependenciesFile,
	dependenciesOf,
} from "./audit-index/audit-index.ts";
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
// Read once, for every reference below.
const packages = readWorkspace(root);
await mkdir(dirname(referenceFile(root)), { recursive: true });
const sections = await sectionsIn(packages);
await writeFile(
	referenceFile(root),
	referenceOf(sections, await clientSectionsOf(root, packages), await idpTypesOf(root, packages)),
);
for (const s of sections) await writeFile(referenceConfFile(s.dir), referenceConfOf(s));
await writeFile(auditReferenceFile(root), auditReferenceOf(await declarationsIn(packages)));
await writeFile(routesFile(root), routesOf(await routesIn(root, packages)));
await writeFile(attackSurfaceFile(root), attackSurfaceOf(await attackSurfaceIn(root, packages)));
const entries = auditIndexIn(root, packages);
await mkdir(dirname(cardsFile(root)), { recursive: true });
await writeFile(cardsFile(root), cardsOf(entries));
await writeFile(dependenciesFile(root), dependenciesOf(entries));
