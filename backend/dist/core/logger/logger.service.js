"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ChocoletLoggerService = void 0;
const common_1 = require("@nestjs/common");
let ChocoletLoggerService = class ChocoletLoggerService {
    log(message, context, prefix) {
        if (!prefix)
            prefix = "Nest";
        console.log(`\x1b[32m[${prefix}]\x1b[0m \x1b[37m${new Date().toLocaleString()}\x1b[0m \x1b[32mLOG\x1b[0m \x1b[33m[${context}]\x1b[0m \x1b[32m${message}\x1b[0m`);
    }
    info(message, context, prefix) {
        if (!prefix)
            prefix = "Nest";
        console.info(`\x1b[36m[${prefix}]\x1b[0m \x1b[37m${new Date().toLocaleString()}\x1b[0m \x1b[36mINFO\x1b[0m \x1b[33m[${context}]\x1b[0m \x1b[36m${message}\x1b[0m`);
    }
    warn(message, context, prefix) {
        if (!prefix)
            prefix = "Nest";
        console.warn(`\x1b[33m[${prefix}]\x1b[0m \x1b[37m${new Date().toLocaleString()}\x1b[0m \x1b[33mWARN\x1b[0m \x1b[33m[${context}]\x1b[0m \x1b[33m${message}\x1b[0m`);
    }
    error(message, trace, context, prefix) {
        if (!prefix)
            prefix = "Nest";
        console.error(`\x1b[31m[${prefix}]\x1b[0m \x1b[37m${new Date().toLocaleString()}\x1b[0m \x1b[31mERROR\x1b[0m \x1b[33m[${context}]\x1b[0m \x1b[31m${message}\x1b[0m`, trace);
    }
    debug(message, context, prefix) {
        if (!prefix)
            prefix = "Nest";
        console.log(`\x1b[35m[${prefix}]\x1b[0m \x1b[37m${new Date().toLocaleString()}\x1b[0m \x1b[35mDEBUG\x1b[0m \x1b[33m[${context}]\x1b[0m \x1b[35m${message}\x1b[0m`);
    }
    verbose(message, context, prefix) {
        if (!prefix)
            prefix = "Nest";
        console.log(`\x1b[34m[${prefix}]\x1b[0m \x1b[37m${new Date().toLocaleString()}\x1b[0m \x1b[34mVERBOSE\x1b[0m \x1b[33m[${context}]\x1b[0m \x1b[34m${message}\x1b[0m`);
    }
};
exports.ChocoletLoggerService = ChocoletLoggerService;
exports.ChocoletLoggerService = ChocoletLoggerService = __decorate([
    (0, common_1.Injectable)()
], ChocoletLoggerService);
//# sourceMappingURL=logger.service.js.map