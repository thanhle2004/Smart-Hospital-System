import {
    Injectable,
    UnauthorizedException,
    ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { HashService } from 'src/shared/services/hash.service';
import type { SignOptions } from 'jsonwebtoken';
import { env } from 'src/config/env';
import { Role } from '@prisma/client';
import type { CreateRegisterDto } from './dto/register.dto';
import type { CreateLoginDto } from './dto/login.dto';
import { AuthResponseDto, userResponseSchema } from './dto/response.dto';
import { AuthRepository } from './auth.repository';

@Injectable()
export class AuthService {
    constructor(
        private readonly repo: AuthRepository,
        private readonly jwt: JwtService,
        private readonly hashService: HashService,
    ) { }

    private accessExpiresIn = env.ACCESS_TOKEN_EXPIRES_IN as SignOptions['expiresIn'];
    private refreshExpiresIn = env.REFRESH_TOKEN_EXPIRES_IN as SignOptions['expiresIn'];

    private signAccessToken(user: { id: string; email: string; role?: string }) {
        return this.jwt.sign(
            { sub: user.id, email: user.email, role: user.role },
            { secret: env.JWT_ACCESS_SECRET, expiresIn: this.accessExpiresIn },
        );
    }

    private signRefreshToken(user: { id: string; email: string; role?: string }) {
        return this.jwt.sign(
            { sub: user.id, email: user.email, role: user.role },
            { secret: env.JWT_REFRESH_SECRET, expiresIn: this.refreshExpiresIn },
        );
    }

    async register(data: CreateRegisterDto): Promise<AuthResponseDto> {
        const { email, password, role } = data;
        const existing = await this.repo.findUserByEmail(email);
        if (existing) throw new ConflictException('Email already exists');

        const passwordHash = await this.hashService.hash(password);

        const user = await this.repo.createUser({ email, passwordHash, role: role as Role });

        const accessToken = this.signAccessToken(user);
        const refreshToken = this.signRefreshToken(user);

        const tokenHash = await this.hashService.hash(refreshToken);
        await this.repo.createRefreshToken({
            userId: user.id,
            tokenHash,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        return {
            user: userResponseSchema.parse(user),
            accessToken,
            refreshToken,
        };
    }

    async login(data: CreateLoginDto): Promise<AuthResponseDto> {
        const { email, password } = data;
        const user = await this.repo.findAuthUserByEmail(email);
        const dummyHash = '$2b$10$C6k7i35S3uK0.XPBm7P6du5A.96.Hk5C6k7i35S3uK0.XPBm7P6du';
    
        const hashToCompare = user ? user.passwordHash : dummyHash;
        const isMatch = await this.hashService.compare(password, hashToCompare);

        if (!user || !isMatch) {
            throw new UnauthorizedException('Incorrect email or password. Please try again.');
        }

        const accessToken = this.signAccessToken(user);
        const refreshToken = this.signRefreshToken(user);

        const tokenHash = await this.hashService.hash(refreshToken);
        await this.repo.createRefreshToken({
            userId: user.id,
            tokenHash,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        return {
            user: userResponseSchema.parse(user),
            accessToken,
            refreshToken,
        };
    }

    async refresh(refreshToken: string) {
        let payload: any;
        try {
            payload = this.jwt.verify(refreshToken, { secret: env.JWT_REFRESH_SECRET });
        } catch {
            throw new UnauthorizedException('Invalid refresh token');
        }

        const userId = payload.sub;

        //Find matching token in DB (using hash comparison) which is not revoked and not expired
        const tokens = await this.repo.findRefreshTokens(userId, 10);

        const matched = await Promise.any(
            tokens.map(async (t) => 
                (await this.hashService.compare(refreshToken, t.tokenHash)) ? t : Promise.reject()
            ),
        ).catch(() => null);

        if (!matched) throw new UnauthorizedException('Refresh token not found');

        //Use transaction to revoke old token and create new one atomically
        return this.repo.transaction(async (tx) => {
            await this.repo.revokeRefreshToken(matched.id, tx);

            const user = await this.repo.findAuthUserById(userId, tx);
            if (!user) throw new UnauthorizedException('User not found');

            const newAccessToken = this.signAccessToken(user);
            const newRefreshToken = this.signRefreshToken(user);
            const newTokenHash = await this.hashService.hash(newRefreshToken);

            await this.repo.createRefreshToken({
                userId: user.id,
                tokenHash: newTokenHash,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            }, tx);

            return { 
                user: userResponseSchema.parse(user),
                accessToken: newAccessToken, 
                refreshToken: newRefreshToken 
            };
        });
    }

    async logout(userId: string, refreshToken?: string) {
        if (refreshToken) {
            const tokens = await this.repo.findRefreshTokens(userId, 20);

            for (const t of tokens) {
                if (await this.hashService.compare(refreshToken, t.tokenHash)) {
                    await this.repo.deleteRefreshToken(t.id);
                    break;
                }
            }
        } else {
            await this.repo.deleteRefreshTokensByUser(userId);
        }

        return { message: 'Logged out' };
    }

    async me(userId: string) {
        return this.repo.findUserById(userId);
    }

    async verifyPassword(userId: string, password: string) {
        const user = await this.repo.findPasswordHashById(userId);

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        const matched = await this.hashService.compare(password, user.passwordHash);
        if (!matched) {
            throw new UnauthorizedException('Incorrect password');
        }

        return { verified: true };
    }
}