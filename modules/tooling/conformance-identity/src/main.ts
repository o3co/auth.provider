import "./new.ts";
import "./legacy.ts";

export {
	httpLedger,
	type IdentityPart,
	identityArea,
	type LedgerScene,
	ledgerRevocation,
	type RevocationScene,
	recentAuthenticationWindow,
	type UpstreamScene,
	type UserScene,
} from "./area.ts";
export { pastBoundaries, revocationWindowMs } from "./revocation.ts";
