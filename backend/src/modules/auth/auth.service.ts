import {
    Injectable,
    UnauthorizedException,
    ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import type { SignOptions } from 'jsonwebtoken';
import { env } from 'src/config/env';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService) { }
    private accessExpiresIn = env.ACCESS_TOKEN_EXPIRES_IN as SignOptions['expiresIn'];
    private refreshExpiresIn = env.REFRESH_TOKEN_EXPIRES_IN as SignOptions['expiresIn'];
    private signAccessToken(user: { id: string; email: string; role?: string }) {
        return this.jwt.sign(
            { sub: user.id, email: user.email, role: user.role },
            { secret: process.env.JWT_ACCESS_SECRET!, expiresIn: this.accessExpiresIn },
        );
    }

    private signRefreshToken(user: { id: string; email: string; role?: string }) {
        return this.jwt.sign(
            { sub: user.id, email: user.email, role: user.role },
            { secret: process.env.JWT_REFRESH_SECRET!, expiresIn: this.refreshExpiresIn },
        );
    }

    async register(email: string, password: string) {
        const existing = await this.prisma.user.findUnique({ where: { email } });
        if (existing) throw new ConflictException('Email already exists');

        const passwordHash = await bcrypt.hash(password, 10);

        const user = await this.prisma.user.create({
            data: { email, passwordHash },
        });

        return { id: user.id, email: user.email };
    }

    async login(email: string, password: string) {
        const user = await this.prisma.user.findUnique({ where: { email } });
        if (!user) throw new UnauthorizedException('Invalid credentials');

        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) throw new UnauthorizedException('Invalid credentials');

        const accessToken = this.signAccessToken(user);
        const refreshToken = this.signRefreshToken(user);

        const tokenHash = await bcrypt.hash(refreshToken, 10);
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7d (đơn giản)

        await this.prisma.refreshToken.create({
            data: { userId: user.id, tokenHash, expiresAt },
        });

        return { accessToken, refreshToken };
    }

    async refresh(refreshToken: string) {
        // verify refresh jwt signature
        let payload: any;
        try {
            payload = this.jwt.verify(refreshToken, {
                secret: process.env.JWT_REFRESH_SECRET!,
            });
        } catch {
            throw new UnauthorizedException('Invalid refresh token');
        }

        const userId = payload.sub as string;

        // find valid token in DB by comparing hash
        const tokens = await this.prisma.refreshToken.findMany({
            where: { userId, expiresAt: { gt: new Date() } },
            orderBy: { createdAt: 'desc' },
            take: 10,
        });

        const matched = await Promise.any(
            tokens.map(async (t) => ((await bcrypt.compare(refreshToken, t.tokenHash)) ? t : Promise.reject())),
        ).catch(() => null);

        if (!matched) throw new UnauthorizedException('Refresh token not found');

        // rotate: delete matched token, create new
        await this.prisma.refreshToken.delete({ where: { id: matched.id } });

        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user) throw new UnauthorizedException('User not found');

        const newAccessToken = this.signAccessToken(user);
        const newRefreshToken = this.signRefreshToken(user);

        await this.prisma.refreshToken.create({
            data: {
                userId: user.id,
                tokenHash: await bcrypt.hash(newRefreshToken, 10),
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            },
        });

        return { accessToken: newAccessToken, refreshToken: newRefreshToken };
    }

    async logout(userId: string, refreshToken?: string) {
        // nếu có refreshToken thì chỉ revoke 1 cái; còn không thì revoke all
        if (refreshToken) {
            const tokens = await this.prisma.refreshToken.findMany({
                where: { userId },
                take: 20,
                orderBy: { createdAt: 'desc' },
            });

            for (const t of tokens) {
                if (await bcrypt.compare(refreshToken, t.tokenHash)) {
                    await this.prisma.refreshToken.delete({ where: { id: t.id } });
                    break;
                }
            }
        } else {
            await this.prisma.refreshToken.deleteMany({ where: { userId } });
        }

        return { message: 'Logged out' };
    }
}