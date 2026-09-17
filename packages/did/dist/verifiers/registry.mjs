export class VerifierRegistry {
    factories = new Map();
    register(algorithm, factory) {
        this.factories.set(algorithm, factory);
    }
    get(algorithm) {
        return this.factories.get(algorithm);
    }
    has(algorithm) {
        return this.factories.has(algorithm);
    }
    algorithms() {
        return [...this.factories.keys()];
    }
}
