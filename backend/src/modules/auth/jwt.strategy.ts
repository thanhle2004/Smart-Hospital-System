import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';

function cookieExtractor(req: Request): string | null {
    return req?.cookies?.[process.env.COOKIE_ACCESS ?? 'access_token'] ?? null;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor() {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                cookieExtractor,
                ExtractJwt.fromAuthHeaderAsBearerToken(),
            ]),
            secretOrKey: process.env.JWT_ACCESS_SECRET!,
        });
    }

    async validate(payload: any) {
        if (!payload?.sub) throw new UnauthorizedException();
        return { userId: payload.sub, email: payload.email, role: payload.role };
    }
}