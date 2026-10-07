/**
 * The schema of `jwks {}`, the JWKS module's own section. Each key reads the
 * string its environment variable carries; its defaults are applied where it
 * is read (`resolveJwksPath`, `resolveJwksCacheMaxAge`), so the section may be
 * absent or empty. Strict: an unknown key refuses boot, naming its path.
 */
import { z } from "zod";
export declare const JWKS_SECTION: z.ZodOptional<z.ZodObject<{
    path: z.ZodOptional<z.ZodString & z.ZodType<string, string, z.core.$ZodTypeInternals<string, string>>>;
    cacheMaxAge: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
}, z.core.$strict>>;
//# sourceMappingURL=section.d.mts.map