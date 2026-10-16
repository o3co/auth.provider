#!/usr/bin/env node
import { run } from "./command.ts";

process.exitCode = await run(process.argv.slice(2));
