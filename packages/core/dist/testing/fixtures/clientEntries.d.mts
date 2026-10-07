import type { z } from "zod";
import type { ClientEntry, ClientEntrySchema } from "../../repositories/InMemoryClientRepository.mjs";
/**
 * Client entries as a registration file gives them: the schema's input, its
 * defaults left out. `InMemoryClientRepository` parses each entry, so it takes
 * this form, though its parameter is typed with the schema's output.
 */
export declare const clientEntries: (entries: Iterable<readonly [string, z.input<typeof ClientEntrySchema>]>) => Map<string, ClientEntry>;
//# sourceMappingURL=clientEntries.d.mts.map