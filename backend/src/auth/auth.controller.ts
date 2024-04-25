/*import { Body, Controller, Delete, HttpCode, HttpStatus, Post } from "@nestjs/common";
import { Public } from "src/core/decorator";
import { ApiResponse, ApiTags } from "@nestjs/swagger";
import { RegisterDto, LoginDto } from "./dto";
import { RealIp } from "src/core/decorator/realIp.decorator";

@Controller("auth")
@ApiTags("auth")
export class AuthController {
    
    @Public()
    @Post("register")
    @ApiResponse({
        status: HttpStatus.OK,
        description: "A new account has been successfully created."
    })
    register(@Body() dto: RegisterDto, @RealIp() ip: string) {
        return this.authService.register(dto, ip);
    }
}*/