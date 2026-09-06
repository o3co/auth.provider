import { ContainerRuntimeClient } from "../container-runtime";
/**
 * Resolve the Ryuk reaper image name. Read lazily so that callers (and tests)
 * can set `process.env.RYUK_CONTAINER_IMAGE` _after_ this module is imported —
 * including via `.env` files loaded by `dotenv` at runtime.
 *
 * See https://github.com/testcontainers/testcontainers-node/issues/1310.
 */
export declare function getReaperImage(): string;
export interface Reaper {
    sessionId: string;
    containerId: string;
    addSession(sessionId: string): void;
    addComposeProject(projectName: string): void;
}
export declare function getReaper(client: ContainerRuntimeClient): Promise<Reaper>;
