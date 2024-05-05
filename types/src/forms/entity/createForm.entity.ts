export class CreateFormEntity {
    id: string;
    password?: string;
    ipAddress?: string;
    accepterId?: string;

    constructor(partial: Partial<CreateFormEntity>) {
        Object.assign(this, partial);
    }
}
