"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@nestjs/core");
const config_1 = require("@nestjs/config");
const app_module_1 = require("./app.module");
const common_1 = require("@nestjs/common");
const class_validator_1 = require("class-validator");
const swagger_1 = require("@nestjs/swagger");
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    app.enableCors({
        origin: [
            "https://rewrite.chocolet.xyz",
            "https://admin.chocolet.xyz",
            "https://chocolet.xyz"
        ],
        credentials: true
    });
    app.useGlobalPipes(new common_1.ValidationPipe({ forbidNonWhitelisted: true, whitelist: true }));
    app.setGlobalPrefix("/api");
    (0, class_validator_1.useContainer)(app.select(app_module_1.AppModule), { fallbackOnErrors: true });
    const configService = app.get(config_1.ConfigService);
    const config = new swagger_1.DocumentBuilder()
        .setTitle(configService.get("VITE_NAME"))
        .setDescription(configService.get("VITE_DESCRIPTION"))
        .setVersion(configService.get("VITE_VERSION"))
        .addBearerAuth({
        type: "apiKey",
        name: "Authorization",
        in: "header",
        description: "Auth token, no prefix"
    }, "Authorization")
        .build();
    const document = swagger_1.SwaggerModule.createDocument(app, config);
    swagger_1.SwaggerModule.setup("api/docs", app, document);
    await app.listen(configService.get("SERVER_PORT"));
}
bootstrap();
//# sourceMappingURL=main.js.map