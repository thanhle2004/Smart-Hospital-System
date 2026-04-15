import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { CreateVisitFlowDto } from './dto/create-visit-flow.dto';
import { UpdateVisitFlowDto } from './dto/update-visit-flow.dto';
import { Prisma, VisitRoomStatusEnum, VisitFlow } from '@prisma/client';
import { VisitFlowRepository } from './visit-flow.repository';

@Injectable()
export class VisitFlowService {
  constructor(private readonly repo: VisitFlowRepository) {}

  private async assertStepMutable(visitId: string, roomTypeId: number) {
    const lockedVisitRoom = await this.repo.findLockedVisitRoom(visitId, roomTypeId);

    if (!lockedVisitRoom) return;

    if (lockedVisitRoom.status === VisitRoomStatusEnum.IN_PROGRESS) {
      throw new ConflictException('Cannot modify a step that is currently in progress');
    }

    throw new ConflictException('Cannot modify a step that has already been completed');
  }

  //////////////////////////////////////////////////
  // COPY FROM TEMPLATE (used at check-in)
  //////////////////////////////////////////////////
  async copyFromTemplate(
    visitId: string,
    flowId: number,
    tx: Prisma.TransactionClient = undefined as never,
  ) {
    const flowRooms = await this.repo.findFlowRooms(flowId, tx);

    const visitFlows: VisitFlow[] = [];

    // Deduplicate flowRooms by roomTypeId, keeping the first occurrence
    const uniqueFlowRooms = Array.from(
      new Map(flowRooms.map(fr => [fr.roomTypeId, fr])).values()
    );

    for (const fr of uniqueFlowRooms) {
      // Check if VisitFlow already exists
      const existingVF = await this.repo.findVisitFlowByVisitRoom(visitId, fr.roomTypeId, tx);

      if (!existingVF) {
        const vf = await this.repo.createVisitFlow(visitId, fr.roomTypeId, fr.defaultOrder, false, tx);
        visitFlows.push(vf);
      } else {
        visitFlows.push(existingVF);
      }
    }

    const dependencies = await this.repo.findFlowDependencies(flowId, tx);

    for (const dep of dependencies) {
      const main = visitFlows.find((v) => v.roomTypeId === dep.roomTypeId);
      const required = visitFlows.find((v) => v.roomTypeId === dep.requiredRoomTypeId);

      if (main && required) {
        // Check if dependency already exists
        const existingDep = await tx.visitFlowDependency.findFirst({
          where: {
            visitFlowId: main.id,
            requiredVisitFlowId: required.id,
          },
        });

        if (!existingDep) {
          await tx.visitFlowDependency.create({
            data: {
              visitFlowId: main.id,
              requiredVisitFlowId: required.id,
            },
          });
        }
      }
    }
  }

  //////////////////////////////////////////////////
  // FIND BY VISIT
  //////////////////////////////////////////////////
  async findByVisit(visitId: string) {
    const [steps, visitRooms] = await Promise.all([
      this.repo.findVisitFlowsDetailedByVisit(visitId),
      this.repo.findVisitRoomsByVisit(visitId),
    ]);

    const completedRoomTypeIds = new Set(
      visitRooms
        .filter((vr) => vr.status === 'COMPLETED' && vr.roomTypeId != null)
        .map((vr) => vr.roomTypeId),
    );

    const inProgressRoomTypeIds = new Set(
      visitRooms
        .filter((vr) => vr.status === 'IN_PROGRESS' && vr.roomTypeId != null)
        .map((vr) => vr.roomTypeId),
    );

    return steps.map((step) => ({
      ...step,
      isCompleted: completedRoomTypeIds.has(step.roomTypeId),
      isInProgress: inProgressRoomTypeIds.has(step.roomTypeId),
    }));
  }

  //////////////////////////////////////////////////
  // ADD ROOM MANUALLY (matches @Post('visit/:visitId/rooms'))
  //////////////////////////////////////////////////
  async addRoomToVisit(visitId: string, roomTypeId: number) {
    // Check whether the visit exists
    const visit = await this.repo.findVisitById(visitId);
    if (!visit) throw new NotFoundException('Visit not found');

    // Check whether this room type already exists in the flow (prevent duplicates)
    const existing = await this.repo.findVisitFlowByVisitRoom(visitId, roomTypeId);
    if (existing) throw new ConflictException('This room type is already in the visit flow');

    // Get current max orderIndex and append to the end
    const lastStep = await this.repo.findLastVisitFlowByVisit(visitId);

    const newOrder = (lastStep?.orderIndex ?? 0) + 1;

    return this.repo.createVisitFlow(visitId, roomTypeId, newOrder, true);
  }

  //////////////////////////////////////////////////
  // SKIP STEP (matches @Patch(':id/skip'))
  //////////////////////////////////////////////////
  async skip(id: number) {
    const existing = await this.repo.findVisitFlowById(id);
    if (!existing) throw new NotFoundException('VisitFlow step not found');

    await this.assertStepMutable(existing.visitId, existing.roomTypeId);

    return this.repo.updateVisitFlow(id, { isSkipped: true } as UpdateVisitFlowDto);
  }

  async unskip(id: number) {
    const existing = await this.repo.findVisitFlowById(id);
    if (!existing) throw new NotFoundException('VisitFlow step not found');

    await this.assertStepMutable(existing.visitId, existing.roomTypeId);

    return this.repo.updateVisitFlow(id, { isSkipped: false } as UpdateVisitFlowDto);
  }

  async skipAllExcept(visitId: string, keepVisitFlowId: number) {
    return this.repo.transaction(async (tx) => {
      const steps = await tx.visitFlow.findMany({
        where: { visitId },
        select: { id: true, roomTypeId: true },
      });

      const keepStep = steps.find((s) => s.id === keepVisitFlowId);
      if (!keepStep) {
        throw new NotFoundException('Target visit flow step not found in this visit');
      }

      const requiredDeps = await this.repo.findVisitFlowDependenciesByStep(keepVisitFlowId, tx);

      if (requiredDeps.length > 0) {
        const requiredStepIds = requiredDeps.map((d) => d.requiredVisitFlowId);
        const requiredSteps = await tx.visitFlow.findMany({
          where: {
            id: { in: requiredStepIds },
            visitId,
          },
          select: {
            id: true,
            roomTypeId: true,
          },
        });

        const completedVisitRooms = await tx.visitRoom.findMany({
          where: {
            visitId,
            status: 'COMPLETED',
            roomTypeId: { not: null },
          },
          select: { roomTypeId: true },
        });

        const completedRoomTypeIds = new Set(
          completedVisitRooms
            .filter((vr) => vr.roomTypeId != null)
            .map((vr) => vr.roomTypeId),
        );

        const hasUnmetDependency = requiredSteps.some(
          (step) => !completedRoomTypeIds.has(step.roomTypeId),
        );

        if (hasUnmetDependency) {
          throw new ConflictException(
            'Cannot skip others for this step because required dependencies are not completed',
          );
        }
      }

      const lockedVisitRooms = await tx.visitRoom.findMany({
        where: {
          visitId,
          status: {
            in: ['IN_PROGRESS', 'COMPLETED'],
          },
        },
        select: { roomTypeId: true },
      });

      const lockedRoomTypeIds = new Set(
        lockedVisitRooms
          .filter((vr) => vr.roomTypeId != null)
          .map((vr) => vr.roomTypeId),
      );

      const mutableSteps = steps.filter((s) => !lockedRoomTypeIds.has(s.roomTypeId));
      const skipIds = mutableSteps
        .filter((s) => s.id !== keepVisitFlowId)
        .map((s) => s.id);

      if (skipIds.length > 0) {
        await this.repo.updateVisitFlowsByIds(skipIds, tx);
      }

      const keepIsMutable = !lockedRoomTypeIds.has(keepStep.roomTypeId);
      if (keepIsMutable) {
        await this.repo.updateVisitFlow(keepVisitFlowId, { isSkipped: false } as UpdateVisitFlowDto, tx);
      }

      const refreshed = await this.repo.findVisitFlowsByVisit(visitId, tx);

      return refreshed;
    });
  }

  //////////////////////////////////////////////////
  // BASIC CRUD
  //////////////////////////////////////////////////

  async create(dto: CreateVisitFlowDto) {
    const requiredVisitFlowIds = Array.from(new Set(dto.requiredVisitFlowIds ?? []));

    return this.repo.transaction(async (tx) => {
      if (requiredVisitFlowIds.length > 0) {
        const requiredSteps = await tx.visitFlow.findMany({
          where: {
            id: { in: requiredVisitFlowIds },
            visitId: dto.visitId,
          },
          select: { id: true },
        });

        if (requiredSteps.length !== requiredVisitFlowIds.length) {
          throw new NotFoundException('Some required dependency steps do not exist in this visit');
        }
      }

      const created = await this.repo.createVisitFlowStep(dto, tx);

      if (requiredVisitFlowIds.length > 0) {
        await this.repo.createDependencies(created.id, requiredVisitFlowIds, tx);
      }

      return this.repo.findVisitFlowWithRelations(created.id, tx);
    });
  }

  async update(id: number, dto: UpdateVisitFlowDto) {
    const existing = await this.repo.findVisitFlowById(id);
    if (!existing) throw new NotFoundException('VisitFlow not found');

    return this.repo.updateVisitFlow(id, dto);
  }

  async remove(id: number) {
    const existing = await this.repo.findVisitFlowById(id);
    if (!existing) throw new NotFoundException('VisitFlow not found');

    await this.assertStepMutable(existing.visitId, existing.roomTypeId);

    // Remove related dependencies before deleting the flow step (avoid FK constraint errors)
    await this.repo.deleteVisitFlowDependenciesByVisitFlow(id);

    return this.repo.deleteVisitFlow(id);
  }
}