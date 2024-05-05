export enum HttpStatus {
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    INTERNAL_SERVER_ERROR = 500,
}

export class Exceptions extends Error {
    constructor(public status: HttpStatus, public message: string) {
        super(message);
        Object.setPrototypeOf(this, Exceptions.prototype);
    }
}
