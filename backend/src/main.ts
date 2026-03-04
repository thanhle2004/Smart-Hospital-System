import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(cookieParser());

  app.enableCors({
    origin: 'http://localhost:3000',
    credentials: true,
  });

  const config = new DocumentBuilder()
    .setTitle('Monorepo API')
    .setDescription('API documentation for Monorepo project')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  const port = process.env.PORT ?? 5000;
  await app.listen(port);

  console.log("🌐 Frontend running at: http://localhost:3000");
  console.log(`🚀 Backend running on http://localhost:${port}`);
  console.log(`📘 Swagger docs at http://localhost:${port}/docs`);
}
bootstrap();