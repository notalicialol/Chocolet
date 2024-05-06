import { Controller, Get, Request, UseGuards } from "@nestjs/common";
import { AuthGuard } from "./auth/auth.guard";
import { JwtAuthGuard } from "./auth/jwt-auth.guard";

@Controller("protected")
@UseGuards(AuthGuard)
export class AppController {
  @Get()
  getProtectedResource() {
    return "This is a protected route.";
  }

  @Get("specific")
  @UseGuards(AuthGuard)
  getSpecificResource() {
    return "This is another protected route.";
  }

  @UseGuards(JwtAuthGuard)
  @Get("profile")
  getProfile(@Request() req : any) {
    return req.user;
  }
}
