import {
  Body,
  Controller,
  Get,
  Post,
  Res,
  Req,
  UseGuards,
  UnauthorizedException,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import { z } from 'zod';
import { AuthService } from './auth.service';
import { CurrentUser } from './current-user.decorator';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import * as loginDto from './dto/login.dto';
import * as registerDto from './dto/register.dto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { env } from 'src/config/env';

const COOKIE_ACCESS = env.COOKIE_ACCESS ?? 'access_token';
const COOKIE_REFRESH = env.COOKIE_REFRESH ?? 'refresh_token';

const verifyPasswordSchema = z.object({
  password: z.string().min(1),
});

function cookieOpts() {
  const isProd = env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
  } as const;
}

@Controller('auth')
export class AuthController {
  constructor(private auth: AuthService) {}

  // ───────────────── REGISTER ─────────────────
  @Post('register')
  async register(
    @Body(new ZodValidationPipe(registerDto.createRegisterSchema))
    dto: registerDto.CreateRegisterDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.auth.register(dto);

    this.setCookies(res, result.accessToken, result.refreshToken);

    return result;
  }

    // ───────────────── LOGIN ─────────────────
  @Post('login')
  async login(
    @Body(new ZodValidationPipe(loginDto.createLoginSchema))
    dto: loginDto.CreateLoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const result = await this.auth.login(dto);

      this.setCookies(res, result.accessToken, result.refreshToken);

      return result;
    } catch (error) {
      
      res.clearCookie(COOKIE_ACCESS, cookieOpts());
      res.clearCookie(COOKIE_REFRESH, cookieOpts());
      throw error;
    }
  }

  // ───────────────── REFRESH ─────────────────
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const rt = req.cookies?.[COOKIE_REFRESH];

    if (!rt) throw new UnauthorizedException('Missing refresh token');

    const result = await this.auth.refresh(rt);

    this.setCookies(res, result.accessToken, result.refreshToken);

    return result;
  }

  // ───────────────── LOGOUT ─────────────────
  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(
    @CurrentUser() user: { userId: string },
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const rt = req.cookies?.[COOKIE_REFRESH];

    await this.auth.logout(user.userId, rt);

    res.clearCookie(COOKIE_ACCESS, cookieOpts());
    res.clearCookie(COOKIE_REFRESH, cookieOpts());

    return { message: 'Logged out successfully' };
  }

  // ───────────────── ME ─────────────────
  @Get('me')
  @UseGuards(JwtAuthGuard)
  me(@CurrentUser() user: any) {
    return this.auth.me(user.userId);
  }

  // ───────────────── VERIFY PASSWORD ─────────────────
  @Post('verify-password')
  @UseGuards(JwtAuthGuard)
  verifyPassword(
    @CurrentUser() user: { userId: string },
    @Body(new ZodValidationPipe(verifyPasswordSchema))
    body: z.infer<typeof verifyPasswordSchema>,
  ) {
    return this.auth.verifyPassword(user.userId, body.password);
  }

  // ───────────────── SET COOKIE ─────────────────
  private setCookies(
    res: Response,
    accessToken: string,
    refreshToken: string,
  ) {
    res.clearCookie(COOKIE_ACCESS, cookieOpts());
    res.clearCookie(COOKIE_REFRESH, cookieOpts());

    res.cookie(COOKIE_ACCESS, accessToken, {
      ...cookieOpts(),
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie(COOKIE_REFRESH, refreshToken, {
      ...cookieOpts(),
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
  }
}
