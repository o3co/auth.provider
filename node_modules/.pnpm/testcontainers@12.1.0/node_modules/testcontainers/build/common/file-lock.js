"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.withFileLock = withFileLock;
const promises_1 = require("fs/promises");
const path_1 = __importDefault(require("path"));
const proper_lockfile_1 = __importDefault(require("proper-lockfile"));
const tmp_1 = __importDefault(require("tmp"));
const logger_1 = require("./logger");
async function withFileLock(fileName, fn) {
    const file = await createEmptyTmpFile(fileName);
    let releaseLockFn;
    try {
        logger_1.log.debug(`Acquiring lock file "${file}"...`);
        releaseLockFn = await proper_lockfile_1.default.lock(file, {
            retries: { forever: true, factor: 1, minTimeout: 500, maxTimeout: 3000, randomize: true },
        });
        logger_1.log.debug(`Acquired lock file "${file}"`);
        return await fn();
    }
    finally {
        if (releaseLockFn) {
            logger_1.log.debug(`Releasing lock file "${file}"...`);
            await releaseLockFn();
            logger_1.log.debug(`Released lock file "${file}"`);
        }
    }
}
async function createEmptyTmpFile(fileName) {
    const file = path_1.default.resolve(tmp_1.default.tmpdir, fileName);
    await (0, promises_1.writeFile)(file, "");
    return file;
}
