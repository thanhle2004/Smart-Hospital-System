import { Controller, Post, Body, Param, Get, Query, ParseIntPipe, Req, Res, UnauthorizedException } from '@nestjs/common';
import { VisitService } from './visit.service';
import type { Request, Response } from 'express';

const VISIT_ACCESS_COOKIE = 'visit_access_token';

function getVisitCookieOptions() {
  const maxAgeMs = Number(process.env.VISIT_ACCESS_COOKIE_MAX_AGE_MS || 24 * 60 * 60 * 1000);
  const isProd = process.env.NODE_ENV === 'production';

  return {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax' as const,
    path: '/visit',
    maxAge: maxAgeMs,
  };
}

@Controller('visit')
export class VisitController {
  constructor(private readonly visitService: VisitService) {}

  @Post('check-in')
  async checkIn(@Body() body: any, @Res({ passthrough: true }) res: Response) {
    console.log('CHECKIN BODY:', body);
    const result = await this.visitService.checkIn(body);
    if (result?.visitAccessToken) {
      res.cookie(VISIT_ACCESS_COOKIE, result.visitAccessToken, getVisitCookieOptions());
    }
    return result;
  }

  @Get()
  async getVisitsByPatient(
    @Query('patientId') patientId: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (!patientId) {
      throw new Error('patientId query parameter is required');
    }
    const visits = await this.visitService.getVisitsByPatient(patientId);
    const activeVisit = visits.find(
      (v) => v.status === 'WAITING' || v.status === 'IN_PROGRESS',
    );

    if (activeVisit?.visitAccessToken) {
      res.cookie(VISIT_ACCESS_COOKIE, activeVisit.visitAccessToken, getVisitCookieOptions());
    }

    return visits;
  }

  @Get('central-queue')
  getCentralQueue() {
    return this.visitService.getCentralQueue();
  }

  @Post('visit-room/:id/complete')
  completeVisitRoom(@Param('id', ParseIntPipe) id: number) {
    return this.visitService.completeVisitRoom(id);
  }

  @Get(':id')
  getVisit(
    @Param('id') id: string,
    @Req() req: Request,
  ) {
    const token = req.cookies?.[VISIT_ACCESS_COOKIE];
    if (!token) {
      throw new UnauthorizedException('Missing visit access token cookie');
    }
    return this.visitService.getVisitDetail(id, token);
  }

  @Post('visit-room/:id/call')
  callPatient(@Param('id', ParseIntPipe) id: number) {
    return this.visitService.callPatient(id);
    // WAITING → IN_PROGRESS, set startTime = now()
  }

  @Post('visit-room/:id/skip')
  skipPatient(@Param('id', ParseIntPipe) id: number) {
    return this.visitService.skipPatient(id);
    // → SKIPPED
  }
}