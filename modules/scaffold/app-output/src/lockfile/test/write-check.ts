#!/usr/bin/env node
/** Writes the bundled lockfile check beside its source. */
import { writeFile } from "node:fs/promises";
import { bundledCheck, bundledFile } from "./bundle.ts";

await writeFile(bundledFile, await bundledCheck());
