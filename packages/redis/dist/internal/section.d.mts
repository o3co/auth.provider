/**
 * What the package's store modules share of their own sections: the file that
 * holds their defaults, and the shape of a section that is one key prefix.
 */
import { z } from "zod";
/**
 * The package's `config/reference.conf`, which every store module declares as
 * its section's reference: a new `URL` on each call, so a change made through
 * one answer reaches no manifest.
 */
export declare function redisReference(): URL;
/**
 * A store's section that holds its key namespace alone: strict, filling no
 * default — the package's `config/reference.conf` ships each store's prefix.
 */
export declare const keyPrefixSection: z.ZodObject<{
    keyPrefix: z.ZodString;
}, z.core.$strict>;
//# sourceMappingURL=section.d.mts.map