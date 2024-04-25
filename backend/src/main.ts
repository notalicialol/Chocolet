import { NestFactory } from "@nestjs/core";
import { ConfigService } from "@nestjs/config";
import { AppModule } from "./app.module";

import { ValidationPipe } from "@nestjs/common";
import { useContainer } from "class-validator";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";

async function bootstrap() {
    const app = await NestFactory.create(AppModule);

    app.enableCors({
        origin: [
            "https://rewrite.chocolet.xyz",
            "https://admin.chocolet.xyz",
            "https://chocolet.xyz"
        ],
        credentials: true
    });

    app.useGlobalPipes(new ValidationPipe({ forbidNonWhitelisted: true, whitelist: true }));

    app.setGlobalPrefix("/api");

    useContainer(app.select(AppModule), {fallbackOnErrors: true});

    const configService = app.get(ConfigService);

    const config = new DocumentBuilder()
        .setTitle(configService.get<string>("VITE_NAME"))
        .setDescription(configService.get<string>("VITE_DESCRIPTION"))
        .setVersion(configService.get<string>("VITE_VERSION"))
        .addBearerAuth({
            type: "apiKey",
            name: "Authorization",
            in: "header",
            description: "Auth token, no prefix"
        }, "Authorization")
        .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup("api/docs", app, document);

    await app.listen(configService.get<number>("SERVER_PORT"));
}

bootstrap();