export class OpenPackBlookEntity {
    id: number;

    constructor(partial: Partial<OpenPackBlookEntity>) {
        if (partial) {
            this.id = partial.id;
        }
    }
}
