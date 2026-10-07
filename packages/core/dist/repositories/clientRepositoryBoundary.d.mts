import type { EventLogger } from "../logging/Logger.mjs";
import type { ClientRepository } from "./ClientRepository.mjs";
/** What {@link validatedClientRepository} takes beside the repository. */
export interface ClientRepositoryBoundaryOptions {
    /**
     * Where a refused record is said. Default: `consoleLogger`. Ignored when
     * the repository is already a boundary, which keeps its own.
     */
    readonly logger?: Pick<EventLogger, "warn">;
}
/**
 * `inner` behind the boundary: each record `findById` or `authenticate`
 * answers is read once into a plain copy and held to the registration
 * schema, and the copy is what is answered.
 *
 * - A record that fails is refused: `findById` and `authenticate` reject
 *   with a new {@link ClientRecordRefusedError}. Each refusal writes one
 *   `client_record_refused` warn: the `step` (`find` or `authenticate`), the
 *   client id sanitised and capped, and the reasons, at most ten, each
 *   sanitised and capped (`reasonCount` when more). The record itself is
 *   never logged.
 * - `null` or `undefined` is no record: `null`, silently.
 * - A field whose read throws is refused, as `<field>: unreadable`; what was
 *   thrown is dropped. A throw from the logger changes nothing: the refusal
 *   is still the answer.
 * - The repository's own throw is let through as it was thrown. So is an
 *   inner boundary's refusal, which stays a refusal and is not warned again;
 *   anything else is the store's outage.
 *
 * A layer over the boundary keeps a refusal as long as it lets rejections
 * through unchanged (see the file header). A boundary handed to it is
 * answered as it is, never wrapped twice, so it keeps the logger it was
 * first built with; `options` are not read. The boundary is frozen.
 * Building it reads nothing of `inner`. The boundary is always disposable:
 * disposing it reads `inner`'s `Symbol.asyncDispose` then, and calls it when
 * it is a function.
 *
 * The reasons a refusal logs name the field and an entry's position, never a
 * URI (see the file header). The record object is never logged.
 */
export declare function validatedClientRepository(inner: ClientRepository, options?: ClientRepositoryBoundaryOptions): ClientRepository;
//# sourceMappingURL=clientRepositoryBoundary.d.mts.map