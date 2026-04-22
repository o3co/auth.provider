import { type AdapterFactory } from "../adapters/AdapterFactory.mjs";
import type { KeyStore } from "./KeyStore.mjs";
export type KeyStoreFactory = AdapterFactory<KeyStore>;
export declare function createKeyStoreFactory(): KeyStoreFactory;
export declare function registerBuiltinKeyStores(factory: KeyStoreFactory): void;
//# sourceMappingURL=factory.d.mts.map