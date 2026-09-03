import { z } from "zod";
export declare const deviceGrantConfigSchema: z.ZodObject<{
    oauth: z.ZodObject<{
        deviceAuthorization: z.ZodDefault<z.ZodObject<{
            enabled: z.ZodDefault<z.ZodBoolean>;
            "verification-uri": z.ZodOptional<z.ZodString>;
            "verification-uri-complete": z.ZodDefault<z.ZodBoolean>;
            "code-lifetime-seconds": z.ZodDefault<z.ZodNumber>;
            "polling-interval-seconds": z.ZodDefault<z.ZodNumber>;
            rateLimit: z.ZodDefault<z.ZodObject<{
                limit: z.ZodNumber;
                windowSeconds: z.ZodNumber;
            }, z.core.$strip>>;
            store: z.ZodOptional<z.ZodLiteral<"unsupported">>;
        }, z.core.$strip>>;
    }, z.core.$strip>;
}, z.core.$strip>;
export declare const deviceGrantModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=module.d.mts.map