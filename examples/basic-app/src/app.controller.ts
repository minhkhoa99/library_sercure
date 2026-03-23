import { Controller, Get, Post } from '@nestjs/common';
import { RateLimit, SkipSecurity } from '../../libs/security/src';

@Controller('public')
export class AppController {
  
  // Áp dụng RateLimit tuỳ chọn (Global Mặc Định đã chặn nhưng route này Custom ngắn lộn lại 10/10s)
  @Get('hello')
  @RateLimit({ name: 'hello-rate-limit', keyBy: 'ip', limit: 10, windowMs: 10_000 })
  // @Blockable() // Blockable was not exported in security module, skipped or commented out.
  getHello(): string {
    return 'Hello World!';
  }

  // VD 1 route đăng nhập nhạy cảm (Cần Rate Limit chặt hơn)
  @Post('login')
  @RateLimit({ name: 'login-rate-limit', keyBy: 'ip', limit: 5, windowMs: 60_000 }) // 5 requests / 1 min
  login() {
    return { token: 'jwt-token...' };
  }

  // VD 1 Route không cần check RateLimit / Sec.VD: Kubernetes health check.
  @Get('metrics')
  @SkipSecurity()
  metrics() {
    return 'cpu_usage: 12.3%';
  }
}
