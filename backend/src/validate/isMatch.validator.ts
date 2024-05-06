import { ValidatorConstraint, ValidatorConstraintInterface, ValidationArguments } from "class-validator";

@ValidatorConstraint({ async: false })
export class IsMatchConstraint implements ValidatorConstraintInterface {
    validate(confirmPassword: any, args: ValidationArguments) {
        const [relatedPropertyName] = args.constraints;
        const relatedValue = (args.object as any)[relatedPropertyName];
        return confirmPassword === relatedValue;
    }

    defaultMessage(args: ValidationArguments) {
        return `${args.property} does not match ${args.constraints[0]}`;
    }
}
