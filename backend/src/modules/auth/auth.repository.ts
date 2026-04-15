import { Injectable } from '@nestjs/common';
import { Prisma, Role } from '@prisma/client';
import { PrismaService } from 'src/shared/prisma/prisma.service';

type DbClient = PrismaService | Prisma.TransactionClient;

const authUserSelect = {
  id: true,
  email: true,
  role: true,
  passwordHash: true,
  profile: {
    select: {
      fullName: true,
      avatarUrl: true,
    },
  },
} as const;

@Injectable()
export class AuthRepository {
  constructor(private readonly prisma: PrismaService) {}

  findUserByEmail(email: string, tx: DbClient = this.prisma) {
    return tx.user.findUnique({ where: { email } });
  }

  findAuthUserByEmail(email: string, tx: DbClient = this.prisma) {
    return tx.user.findUnique({ where: { email }, select: authUserSelect });
  }

  findAuthUserById(id: string, tx: DbClient = this.prisma) {
    return tx.user.findUnique({ where: { id }, select: authUserSelect });
  }

  findUserById(id: string, tx: DbClient = this.prisma) {
    return tx.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        role: true,
        profile: {
          select: { fullName: true, avatarUrl: true },
        },
      },
    });
  }

  findPasswordHashById(id: string, tx: DbClient = this.prisma) {
    return tx.user.findUnique({
      where: { id },
      select: { passwordHash: true },
    });
  }

  createUser(data: { email: string; passwordHash: string; role: Role }, tx: DbClient = this.prisma) {
    return tx.user.create({ data });
  }

  createRefreshToken(data: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
  }, tx: DbClient = this.prisma) {
    return tx.refreshToken.create({ data });
  }

  findRefreshTokens(userId: string, take: number, tx: DbClient = this.prisma) {
    return tx.refreshToken.findMany({
      where: { userId, expiresAt: { gt: new Date() }, revokedAt: null },
      orderBy: { createdAt: 'desc' },
      take,
    });
  }

  revokeRefreshToken(id: string, tx: DbClient = this.prisma) {
    return tx.refreshToken.update({
      where: { id },
      data: { revokedAt: new Date() },
    });
  }

  deleteRefreshToken(id: string, tx: DbClient = this.prisma) {
    return tx.refreshToken.delete({ where: { id } });
  }

  deleteRefreshTokensByUser(userId: string, tx: DbClient = this.prisma) {
    return tx.refreshToken.deleteMany({ where: { userId } });
  }

  transaction<T>(callback: (tx: Prisma.TransactionClient) => Promise<T>) {
    return this.prisma.$transaction(callback);
  }
}