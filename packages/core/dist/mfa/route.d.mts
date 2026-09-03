import type { Request, Response, Router } from "express";
import type { MfaProviderFactory, MfaResumeState, MfaTransactionStore } from "./types.mjs";
export interface MfaRouteDeps {
    providerFactory: MfaProviderFactory;
    transactionStore: MfaTransactionStore;
    onAuthorizeResume(req: Request, res: Response, resume: Extract<MfaResumeState, {
        flow: "authorize";
    }> & {
        subject: string;
    }): Promise<void>;
    onFederationResume(req: Request, res: Response, resume: Extract<MfaResumeState, {
        flow: "federation";
    }> & {
        subject: string;
    }): Promise<void>;
    onLoginResume(req: Request, res: Response, resume: Extract<MfaResumeState, {
        flow: "login";
    }> & {
        subject: string;
    }): Promise<void>;
}
export declare function createMfaRouter(express: {
    Router: () => Router;
}, deps: MfaRouteDeps): Router;
//# sourceMappingURL=route.d.mts.map