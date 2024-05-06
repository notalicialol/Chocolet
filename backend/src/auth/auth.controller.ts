import { Controller, Post, Body, Req } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { RegisterDto } from "./dto/register.dto";

@Controller("auth")
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post("register")
    async register(@Body() registerDto: RegisterDto, @Req() req : any) {
        return await this.authService.register(registerDto.username, registerDto.password, req.ip);
    }
}
