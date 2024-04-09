"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@nestjs/core");
const app_module_1 = require("./app.module");
const common_1 = require("@nestjs/common");
const class_validator_1 = require("class-validator");
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    app.enableCors({
        origin: [
            "https://rewrite.chocolet.xyz",
            "https://chocolet.xyz"
        ],
        credentials: true
    });
    app.useGlobalPipes(new common_1.ValidationPipe({ forbidNonWhitelisted: true, whitelist: true }));
    app.setGlobalPrefix("/api");
    (0, class_validator_1.useContainer)(app.select(app_module_1.AppModule), { fallbackOnErrors: true });
    await app.listen(6901);
}
bootstrap();
//# sourceMappingURL=main.js.map