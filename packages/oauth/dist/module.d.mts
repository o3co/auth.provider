import { type ClientRepository, type CodeRepository, type Module } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
type ExpressLike = {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
};
export declare const oauthModule: (params: {
    clientRepository: ClientRepository;
    codeRepository: CodeRepository;
    express?: ExpressLike;
}) => Module;
export {};
//# sourceMappingURL=module.d.mts.map