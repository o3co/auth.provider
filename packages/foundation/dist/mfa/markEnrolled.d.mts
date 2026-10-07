import { type StoreRequestSettings } from "../storeTransport.mjs";
/** Posts `{ subject, enrolled }` to `url`; resolves on a `204` and throws on anything else. */
export declare function markMfaEnrolledAtStore(url: string, settings: StoreRequestSettings, owner: string, subject: string, enrolled: boolean): Promise<void>;
//# sourceMappingURL=markEnrolled.d.mts.map