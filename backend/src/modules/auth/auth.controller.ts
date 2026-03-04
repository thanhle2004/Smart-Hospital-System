import { Body, Controller, Get, Post, Res, Req, UseGuards } from '@nestjs/common';
import type { Response, Request } from 'express';
import { AuthService } from './auth.service';

import { CurrentUser } from './current-user.decorator';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import * as loginDto from './dto/login.dto';
import * as registerDto from './dto/register.dto';
import { JwtAuthGuard } from './jwt-auth.guard';

function cookieOpts() {
    const isProd = process.env.NODE_ENV === 'production';
    return {
        httpOnly: true,
        secure: isProd,           // prod => https
        sameSite: isProd ? 'none' : 'lax', // cross-site cookie in prod
        path: '/',
    } as const;
}

@Controller('auth')
export class AuthController {
    constructor(private auth: AuthService) { }

    @Post('register')
    register(@Body(new ZodValidationPipe(registerDto.registerSchema)) dto: registerDto.RegisterDto) {
        return this.auth.register(dto.email, dto.password);
    }

    @Post('login')
    async login(
        @Body(new ZodValidationPipe(loginDto.loginSchema)) dto: loginDto.LoginDto,
        @Res({ passthrough: true }) res: Response,
    ) {
        const { accessToken, refreshToken } = await this.auth.login(dto.email, dto.password);

        res.cookie(process.env.COOKIE_ACCESS ?? 'access_token', accessToken, {
            ...cookieOpts(),
            maxAge: 15 * 60 * 1000,
        });
        res.cookie(process.env.COOKIE_REFRESH ?? 'refresh_token', refreshToken, {
            ...cookieOpts(),
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        // vẫn trả về JSON cho tiện debug (prod có thể bỏ)
        return { accessToken, refreshToken };
    }

    @Post('refresh')
    async refresh(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        const rt = req.cookies?.[process.env.COOKIE_REFRESH ?? 'refresh_token'];
        if (!rt) throw new Error('Missing refresh token');

        const { accessToken, refreshToken } = await this.auth.refresh(rt);

        res.cookie(process.env.COOKIE_ACCESS ?? 'access_token', accessToken, {
            ...cookieOpts(),
            maxAge: 15 * 60 * 1000,
        });
        res.cookie(process.env.COOKIE_REFRESH ?? 'refresh_token', refreshToken, {
            ...cookieOpts(),
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        return { accessToken, refreshToken };
    }

    @Post('logout')
    @UseGuards(JwtAuthGuard)
    async logout(
        @CurrentUser() user: { userId: string },
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        const rt = req.cookies?.[process.env.COOKIE_REFRESH ?? 'refresh_token'];
        await this.auth.logout(user.userId, rt);

        res.clearCookie(process.env.COOKIE_ACCESS ?? 'access_token', cookieOpts());
        res.clearCookie(process.env.COOKIE_REFRESH ?? 'refresh_token', cookieOpts());

        return { message: 'Logged out' };
    }

    @Get('me')
    @UseGuards(JwtAuthGuard)
    me(@CurrentUser() user: any) {
        return user; // { userId, email, role }
    }
}