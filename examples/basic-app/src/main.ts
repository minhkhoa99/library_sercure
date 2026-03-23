import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Quan trọng: SecurityModule tự apply tất cả APP_GUARD Global.
  // Tuy nhiên, có những Middlewares của Library cần Mount Global
  // Nó sẽ tự tiêm vào Express instance thông qua Module Init.
  
  await app.listen(3000);
  console.log('Test Security App running on http://localhost:3000');
  console.log('Thử DOS 5 lần vào /public/login!');
}
bootstrap();
