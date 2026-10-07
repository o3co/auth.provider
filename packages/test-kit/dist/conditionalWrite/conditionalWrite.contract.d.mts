import { type ConditionalCreateAnswer, type ConditionalRemoveAnswer, type ConditionalReplaceAnswer, type ConditionalSetRemoveAnswer, type StoreGeneration, type Versioned, type VersionedSet } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
/** One key's record-scoped conditional members, as a port exposes them. */
export interface ConditionalRecordTarget<V> {
    /** The port's create path: writes the record, live or not, at a new generation. */
    put(key: string, value: V): Promise<void>;
    getVersioned(key: string): Promise<Versioned<V> | null>;
    replaceIf(key: string, expected: StoreGeneration, value: V): Promise<ConditionalReplaceAnswer>;
    removeIf(key: string, expected: StoreGeneration): Promise<ConditionalRemoveAnswer>;
    /**
     * The port's unconditional writes of one key, by name. Each writes the value
     * it is given at a new generation, or, named in the input's `removals`,
     * removes the key.
     */
    readonly unconditional: Readonly<Record<string, (key: string, value: V) => Promise<void>>>;
}
/** What one case runs over. */
export interface ConditionalRecordHarness<V> {
    readonly store: ConditionalRecordTarget<V>;
    /**
     * The same backend through a second instance: another connection, pool or
     * client. Absent: `store` again. That is right for an in-process store,
     * and gives no cross-process proof.
     */
    readonly second?: ConditionalRecordTarget<V>;
    /**
     * Moves the backend's clock past any retention deadline the store set
     * (`key` names the record the case expires). It never judges what expires,
     * and never deletes.
     */
    readonly forceExpire?: (key: string) => Promise<void>;
    /** A target over the same backend that cannot reach it. */
    readonly unreachable?: () => ConditionalRecordTarget<V>;
    readonly close?: () => Promise<void>;
}
export interface ConditionalRecordContractInput<V> {
    readonly build: () => Promise<ConditionalRecordHarness<V>>;
    /** Two distinct values, built fresh and equal on every call. */
    readonly values: () => readonly [V, V];
    /**
     * Mutates a value in place, each mutable part on its own, leaving a part
     * that is frozen without throwing: proves the store keeps its own copy.
     * Absent for an immutable value.
     */
    readonly mutate?: (value: V) => void;
    /**
     * The names in the target's `unconditional` that remove the key, as a
     * logout does. Every other one must leave the value it was given.
     */
    readonly removals?: readonly string[];
    /**
     * The hooks every harness `build` answers, declared up front, so the case
     * list is fixed when the suite is built. A declared hook that a harness
     * lacks fails its case; an undeclared one adds no case.
     */
    readonly supports?: {
        readonly forceExpire?: boolean;
        readonly unreachable?: boolean;
        /** `unconditional` names every unconditional write of the port. Undeclared: that case is not run. */
        readonly unconditional?: boolean;
    };
}
/** One set-scoped port's conditional members. */
export interface ConditionalSetTarget<T> {
    listVersioned(scope: string): Promise<VersionedSet<T>>;
    /** The port's plain listing, when it has one: must agree with `listVersioned`. */
    list?(scope: string): Promise<readonly T[]>;
    createIf(item: T, expected: StoreGeneration | null): Promise<ConditionalCreateAnswer>;
    removeIf(scope: string, id: string, expected: StoreGeneration): Promise<ConditionalSetRemoveAnswer>;
    /** Unconditional: leaves the set present and empty, at a new generation. */
    reset(scope: string): Promise<void>;
    /** A member's own update, when the port has one: must keep the set's generation. */
    updateMember?(scope: string, id: string): Promise<void>;
    /** The port's unconditional membership writes, by name. */
    readonly unconditional?: Readonly<Record<string, (item: T) => Promise<void>>>;
}
/** What one case runs over. */
export interface ConditionalSetHarness<T> {
    readonly store: ConditionalSetTarget<T>;
    /** The same backend through a second instance. Absent: `store` again, with no cross-process proof. */
    readonly second?: ConditionalSetTarget<T>;
    /**
     * Moves the backend's clock past any retention deadline the store set
     * (`scope` names the set the case expires). It never judges membership,
     * and never deletes: that an emptied set's tombstone expires and a set
     * holding a member does not is the store's own doing.
     */
    readonly forceExpire?: (scope: string) => Promise<void>;
    /** A target over the same backend that cannot reach it. */
    readonly unreachable?: () => ConditionalSetTarget<T>;
    readonly close?: () => Promise<void>;
}
export interface ConditionalSetContractInput<T> {
    readonly build: () => Promise<ConditionalSetHarness<T>>;
    /** `n` distinct items of `scope`, equal on every call with the same arguments. */
    readonly items: (scope: string, n: number) => readonly T[];
    readonly idOf: (item: T) => string;
    /** The scope an item belongs to: every item `items(scope, n)` answers is checked against it. */
    readonly scopeOf: (item: T) => string;
    /**
     * Mutates an item in place, never its id or scope, each mutable part on its
     * own, leaving a part that is frozen without throwing: proves the store
     * keeps its own copy. Absent for an immutable item.
     */
    readonly mutate?: (item: T) => void;
    /**
     * The hooks every harness `build` answers, declared up front, so the case
     * list is fixed when the suite is built. A declared hook that a harness
     * lacks fails its case; an undeclared one adds no case.
     */
    readonly supports?: {
        readonly forceExpire?: boolean;
        readonly unreachable?: boolean;
        /** Every target has `updateMember`. Undeclared: that case is not run. */
        readonly updateMember?: boolean;
        /** Every target has `list`. Undeclared: that case is not run. */
        readonly list?: boolean;
        /** `unconditional` names every unconditional membership write of the port. Undeclared: that case is not run. */
        readonly unconditional?: boolean;
    };
}
/** The cases of the record-scoped conditional-write contract over the harnesses `input` builds. */
export declare function conditionalRecordContract<V>(input: ConditionalRecordContractInput<V>): readonly ContractCase[];
/** The cases of the set-scoped conditional-write contract over the harnesses `input` builds. */
export declare function conditionalSetContract<T>(input: ConditionalSetContractInput<T>): readonly ContractCase[];
//# sourceMappingURL=conditionalWrite.contract.d.mts.map