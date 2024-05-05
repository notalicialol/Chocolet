import { ErrorCodes } from "./ErrorCodes.enum";

export class CustomError extends Error {
    constructor(message: string, public code: ErrorCodes, public context?: any) {
        super(message);
        Object.setPrototypeOf(this, CustomError.prototype);
    }
}
