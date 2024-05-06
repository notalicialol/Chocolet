import { ValidatorConstraint, ValidatorConstraintInterface, ValidationArguments } from "class-validator";

@ValidatorConstraint({ async: true })
export class IsAccessCodeConstraint implements ValidatorConstraintInterface {
    validate(accessCode: any, args: ValidationArguments) {
        const expected = process.env.ACCESS_CODE;
        return accessCode === expected;
    }

    defaultMessage(args: ValidationArguments) {
        return "Access code is incorrect.";
    }
}
