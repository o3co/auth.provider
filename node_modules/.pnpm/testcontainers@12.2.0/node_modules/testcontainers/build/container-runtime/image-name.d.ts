export declare class ImageName {
    readonly registry: string | undefined;
    readonly image: string;
    readonly tag: string;
    readonly digest?: string | undefined;
    readonly string: string;
    private static readonly hexRE;
    constructor(registry: string | undefined, image: string, tag: string, digest?: string | undefined);
    equals(other: ImageName): boolean;
    static fromString(string: string): ImageName;
    private static getRegistry;
    private static isRegistry;
}
