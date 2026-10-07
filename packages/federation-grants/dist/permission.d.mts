import type { Request } from "express";
export declare function allowedConnectionsOf(req: Request): readonly string[];
export declare const allows: (req: Request, connection: string) => boolean;
//# sourceMappingURL=permission.d.mts.map