import { Controller, Post, Body, Param, Get } from '@nestjs/common';
import { VisitService } from './service/visit.service';

@Controller('visit')
export class VisitController {
  constructor(private readonly visitService: VisitService) {}

  @Post('check-in')
  checkIn(@Body() body: any) {
    console.log('CHECKIN BODY:', body);
    return this.visitService.checkIn(body);
  }

  @Post('visit-room/:id/complete')
  completeVisitRoom(@Param('id') id: string) {
    return this.visitService.completeVisitRoom(Number(id));
  }

  @Get(':id')
  getVisit(@Param('id') id: string) {
    return this.visitService.getVisitDetail(Number(id));
  }
}