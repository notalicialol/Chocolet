import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { AppModule } from "./app.module";

import * as dotenv from "dotenv";
import { BadRequestException, ValidationPipe } from "@nestjs/common";

dotenv.config({ path: "../.env" });

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.setGlobalPrefix("api");

  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
    disableErrorMessages: false,
    exceptionFactory: (errors) => {
      return new BadRequestException({
        message: Object.values(errors[0].constraints)[0]
      });
    }
  }));

  const options = new DocumentBuilder()
    .setTitle(process.env.VITE_NAME)
    .setDescription(process.env.VITE_DESCRIPTION)
    .setVersion(process.env.VITE_VERSION)
    .build();
  
  const document = SwaggerModule.createDocument(app, options);

  SwaggerModule.setup("api", app, document);

  await app.listen(process.env.SERVER_PORT);
}
bootstrap();
