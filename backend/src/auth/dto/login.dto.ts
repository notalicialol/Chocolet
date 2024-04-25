import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, Validate } from "class-validator";

export class LoginDto {
    @ApiProperty({ example: "John", description: "The username you would like to use." })
    @IsNotEmpty()
    @Validate((value: string) => value.length > 0 && value.length < 16)
    readonly username: string;
    
    @ApiProperty({ example: "Doe", description: "The password you would like to use." })
    @IsNotEmpty()
    @Validate((value: string) => value.length > 0)
    readonly password: string;
}

export default LoginDto;