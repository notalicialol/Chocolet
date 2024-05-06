import { registerDecorator, ValidationOptions } from "class-validator";
import { IsMatchConstraint } from "./isMatch.validator";

export function IsMatch(property: string, validationOptions?: ValidationOptions) {
    return function (object: Object, propertyName: string) {
        registerDecorator({
            target: object.constructor,
            propertyName: propertyName,
            options: validationOptions,
            constraints: [property],
            validator: IsMatchConstraint,
        });
    };
}
