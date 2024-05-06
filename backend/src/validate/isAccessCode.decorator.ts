import { registerDecorator, ValidationOptions } from "class-validator";
import { IsAccessCodeConstraint } from "./isAccessCode.validator";

export function IsAccessCode(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsAccessCodeConstraint,
    });
  };
}
