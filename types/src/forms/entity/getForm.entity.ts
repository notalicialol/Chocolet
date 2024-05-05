export class GetFormEntity {
    id: string;
    password?: string;
    ipAddress?: string;
    accepterId?: string;

    constructor(partial: Partial<GetFormEntity>) {
        Object.assign(this, partial);
    }
}
