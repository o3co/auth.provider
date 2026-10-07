export interface ImagePullPolicy {
    shouldPull(): boolean | "never";
}
export declare class PullPolicy {
    static defaultPolicy(): ImagePullPolicy;
    static alwaysPull(): ImagePullPolicy;
    static neverPull(): ImagePullPolicy;
}
