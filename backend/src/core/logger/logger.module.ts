import { Module } from "@nestjs/common";
import { ChocoletLoggerService } from "./logger.service";

@Module({
    providers: [ChocoletLoggerService],
    exports: [ChocoletLoggerService]
})

export class LoggerModule {};