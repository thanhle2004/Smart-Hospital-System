import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
} from '@nestjs/common';
import { VisitFlowService } from './visit-flow.service';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import * as createVisitFlowDto from './dto/create-visit-flow.dto';
import * as updateVisitFlowDto from './dto/update-visit-flow.dto';

@Controller('visit-flows')
export class VisitFlowController {
  constructor(private readonly service: VisitFlowService) {}

  @Get('visit/:visitId')
  getByVisit(@Param('visitId') visitId: string) {
    return this.service.findByVisit(visitId);
  }

  @Post('visit/:visitId/rooms')             
  addRoom(
    @Param('visitId') visitId: string,
    @Body() body: { roomTypeId: number },
  ) {
    return this.service.addRoomToVisit(visitId, body.roomTypeId);
  }

  @Patch(':id/skip')                     
  skipStep(@Param('id') id: string) {
    return this.service.skip(Number(id));
  }

  @Patch(':id/unskip')
  unskipStep(@Param('id') id: string) {
    return this.service.unskip(Number(id));
  }

  @Post('visit/:visitId/skip-all-except')
  skipAllExcept(
    @Param('visitId') visitId: string,
    @Body() body: { keepVisitFlowId: number },
  ) {
    return this.service.skipAllExcept(visitId, body.keepVisitFlowId);
  }

  @Post()
  create(
    @Body(new ZodValidationPipe(createVisitFlowDto.createVisitFlowSchema))
    dto: createVisitFlowDto.CreateVisitFlowDto,
  ) {
    return this.service.create(dto);
  }

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body(new ZodValidationPipe(updateVisitFlowDto.updateVisitFlowSchema))
    dto: updateVisitFlowDto.UpdateVisitFlowDto,
  ) {
    return this.service.update(Number(id), dto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.service.remove(Number(id));
  }
}