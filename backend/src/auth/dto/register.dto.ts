import { IsString, Length, Matches, IsBoolean, IsNotEmpty } from "class-validator";
import { IsAccessCode } from "../../validate/isAccessCode.decorator";
import { IsMatch } from "../../validate/isMatch.decorator";

export class RegisterDto {
    @IsString()
    @Length(4, 16, { 
        message: "Username must be between 4 and 16 characters long."
    })
    @Matches(/^[a-zA-Z0-9_-]+$/, {
        message: "Please input a valid username."
    })
    username: string;

    @IsString()
    @Length(6, 25, {
        message: "Password must be between 6 and 25 characters long."
    })
    password: string;

    @IsString()
    @Length(6, 25, {
        message: "Confirmation password must be between 6 and 25 characters long."
    })
    @IsMatch("password", {
        message: "Passwords do not match. Please ensure that the confirm password field is the same as your inital password."
    })
    confirm: string;

    @IsBoolean()
    @IsNotEmpty({
        message: "You must agree to the Terms of Service."
    })
    tosCheck: boolean;

    @IsString()
    @IsAccessCode()
    accessCode: string;
}
