import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma/prisma.service';
import type { CreateUserDto } from './dto/create-user.dto';
import type { UpdateUserDto } from './dto/update-user.dto';

export const userSelect = {
  id: true,
  email: true,
  role: true,
  isActive: true,
  createdAt: true,
  updatedAt: true,
  lastLoginAt: true,
  profile: {
    select: {
      id: true,
      userId: true,
      fullName: true,
      avatarUrl: true,
      bio: true,
      createdAt: true,
      updatedAt: true,
    },
  },
} as const;

type DbClient = PrismaService | Prisma.TransactionClient;

@Injectable()
export class UserRepository {
  constructor(private readonly prisma: PrismaService) {}

  create(dto: CreateUserDto, passwordHash: string, tx: DbClient = this.prisma) {
    return tx.user.create({
      data: {
        email: dto.email,
        passwordHash,
        role: dto.role,
        isActive: dto.isActive,
        ...(dto.profile && {
          profile: {
            create: dto.profile,
          },
        }),
      },
      select: userSelect,
    });
  }

  findAll(tx: DbClient = this.prisma) {
    return tx.user.findMany({ select: userSelect });
  }

  findById(id: string, tx: DbClient = this.prisma) {
    return tx.user.findUnique({
      where: { id },
      select: userSelect,
    });
  }

  update(id: string, dto: UpdateUserDto, tx: DbClient = this.prisma) {
    const profileData = {
      ...(dto.fullName !== undefined ? { fullName: dto.fullName } : {}),
      ...(dto.avatarUrl !== undefined ? { avatarUrl: dto.avatarUrl } : {}),
      ...(dto.bio !== undefined ? { bio: dto.bio } : {}),
    };

    const hasProfileUpdate = Object.keys(profileData).length > 0;

    return tx.user.update({
      where: { id },
      data: {
        ...(dto.email !== undefined ? { email: dto.email } : {}),
        ...(dto.role !== undefined ? { role: dto.role } : {}),
        ...(dto.isActive !== undefined ? { isActive: dto.isActive } : {}),
        ...(hasProfileUpdate
          ? {
              profile: {
                upsert: {
                  create: {
                    fullName: dto.fullName ?? null,
                    avatarUrl: dto.avatarUrl ?? null,
                    bio: dto.bio ?? null,
                  },
                  update: profileData,
                },
              },
            }
          : {}),
      },
      select: userSelect,
    });
  }

  deactivate(id: string, tx: DbClient = this.prisma) {
    return tx.user.update({
      where: { id },
      data: { isActive: false },
      select: userSelect,
    });
  }
}