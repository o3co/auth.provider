import type { TokenBinding } from "../grants/tokenBinding.mjs";
declare global {
    namespace Express {
        interface Request {
            tokenBinding?: TokenBinding;
        }
    }
}
//# sourceMappingURL=express.d.mts.map