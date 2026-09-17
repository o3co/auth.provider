import type { z } from "zod";
export declare const loadYamlMap: <T extends z.ZodTypeAny>(filePath: string, schema: T) => Map<string, z.infer<T>>;
//# sourceMappingURL=loadYamlMap.d.mts.map