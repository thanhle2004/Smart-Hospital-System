import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  Delete,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { PatientService } from './patient.service';
import { z } from 'zod';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import * as createPatientDto from './dto/create-patient.dto';
import * as updatePatientDto from './dto/update-patient.dto';
import type { Request, Response } from 'express';

const PATIENT_SESSION_COOKIE = 'patient_session';

function getPatientSessionCookieOptions() {
  const maxAgeMs = Number(process.env.PATIENT_SESSION_COOKIE_MAX_AGE_MS || 24 * 60 * 60 * 1000);
  const isProd = process.env.NODE_ENV === 'production';

  return {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax' as const,
    path: '/patient',
    maxAge: maxAgeMs,
  };
}

const checkPhoneSchema = z.object({
  phone: z.string().min(1),
});

@Controller('patient')
export class PatientController {
  constructor(private readonly patientService: PatientService) {}

  private getPatientIdFromSession(req: Request) {
    const token = req.cookies?.[PATIENT_SESSION_COOKIE];
    const patientId = this.patientService.resolvePatientIdFromSessionToken(token);
    if (!patientId) {
      throw new UnauthorizedException('Patient session is missing or invalid');
    }
    return patientId;
  }

  @Post()
  async create(
    @Body(new ZodValidationPipe(createPatientDto.createPatientSchema))
    body: createPatientDto.CreatePatientDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const patient = await this.patientService.create(body);
    res.cookie(
      PATIENT_SESSION_COOKIE,
      this.patientService.buildPatientSessionToken(patient.id),
      getPatientSessionCookieOptions(),
    );
    return patient;
  }

  @Get()
  findAll() {
    return this.patientService.findAll();
  }

  @Get('me')
  findCurrent(@Req() req: Request) {
    const patientId = this.getPatientIdFromSession(req);
    return this.patientService.findOne(patientId);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.patientService.findOne(id);
  }

  @Put('me')
  updateCurrent(
    @Req() req: Request,
    @Body(new ZodValidationPipe(updatePatientDto.updatePatientSchema))
    body: updatePatientDto.UpdatePatientDto,
  ) {
    const patientId = this.getPatientIdFromSession(req);
    return this.patientService.update(patientId, body);
  }

  @Put(':id')
  update(
    @Param('id') id: string,
    @Body(new ZodValidationPipe(updatePatientDto.updatePatientSchema))
    body: updatePatientDto.UpdatePatientDto,
  ) {
    return this.patientService.update(id, body);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.patientService.remove(id);
  }

  @Post('check-phone')
  async checkPhone(
    @Body(new ZodValidationPipe(checkPhoneSchema))
    body: z.infer<typeof checkPhoneSchema>,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { phone } = body;
    const result = await this.patientService.checkPhone(phone);
    if (result.patient?.id) {
      res.cookie(
        PATIENT_SESSION_COOKIE,
        this.patientService.buildPatientSessionToken(result.patient.id),
        getPatientSessionCookieOptions(),
      );
    }
    return result;
  }
}