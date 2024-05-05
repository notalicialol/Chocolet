import { IsNotEmpty, Length } from "class-validator";

export class CreateDto {
    @IsNotEmpty({ message: "Username cannot be empty" })
    @Length(4, 16, { message: "Username must be between 4 and 16 characters" })
    readonly username: string;

    @IsNotEmpty({ message: "Password cannot be empty" })
    @Length(6, 25, { message: "Password must be between 6 and 25 characters" })
    readonly password: string;

    @IsNotEmpty({ message: "Reason to play cannot be empty" })
    readonly reasonToPlay: string;

    constructor(username: string, password: string, reasonToPlay: string) {
        this.username = username;
        this.password = password;
        this.reasonToPlay = reasonToPlay;
    }
}
