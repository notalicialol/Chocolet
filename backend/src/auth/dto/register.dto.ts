import { ApiProperty } from "@nestjs/swagger";
import { IsBoolean, IsNotEmpty, Validate } from "class-validator";

export class RegisterDto {
    @ApiProperty({ example: "John", description: "The username you wish to sign up with" })
    @IsNotEmpty()
    @Validate((value: string) => value.length > 0)
    readonly username: string;

    @ApiProperty({ example: "Doe", description: "The password you wish to sign up with" })
    @IsNotEmpty()
    @Validate((value: string) => value.length > 0)
    readonly password: string;

    /*@ApiProperty({ example: "accesscode", description: "A required code used for user validation to check if a user is allowed access during development" })
    @IsNotEmpty()
    @Validate(IsAccessCode)
    readonly accessCode: string;

    @ApiProperty()
    @IsNotEmpty()
    @IsBoolean()
    @Validate((value: boolean) => value === true)
    readonly acceptedTerms: boolean;*/
}

export default RegisterDto;