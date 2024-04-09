import { LoggerService } from "@nestjs/common";
export declare class ChocoletLoggerService implements LoggerService {
    log(message: any, context?: string, prefix?: string): void;
    info(message: any, context?: string, prefix?: string): void;
    warn(message: any, context?: string, prefix?: string): void;
    error(message: any, trace?: string, context?: string, prefix?: string): void;
    debug(message: any, context?: string, prefix?: string): void;
    verbose(message: any, context?: string, prefix?: string): void;
}
