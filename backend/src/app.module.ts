import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './shared/prisma/prisma.module';
import { PatientModule } from './modules/patient/patient.module';
import { UserModule } from './modules/user/user.module';
import { ProfileModule } from './modules/profile/profile.module';
import { PriorityModule } from './modules/priority/priority.module';
import { FlowModule } from './modules/flow/flow.module';
import { RoomModule } from './modules/room/room.module';
import { VisitModule } from './modules/visit/visit.module';
import { PatientTypeModule } from './modules/patient-type/patient-type.module';
import { VisitFlowModule } from './modules/visit-flow/visit-flow.module';
import { SharedModule } from './shared/shared.module';
import { AuthModule } from './modules/auth/auth.module';
import { RoomTypeModule } from './modules/room-type/room-type.module';

@Module({
  imports: [PrismaModule, AuthModule, PatientModule, UserModule, ProfileModule, PriorityModule, FlowModule, RoomModule, VisitModule, PatientTypeModule, VisitFlowModule, SharedModule, RoomTypeModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
