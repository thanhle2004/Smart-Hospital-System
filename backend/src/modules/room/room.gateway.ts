// modules/room/room.gateway.ts
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger } from '@nestjs/common';

// Queue payload shape - matches SocketQueueUpdatedPayload on frontend
export interface QueueUpdatedPayload {
  waiting: any[];
  current: any | null;
}

// Doctors payload shape - matches SocketDoctorsUpdatedPayload on frontend
export interface DoctorsUpdatedPayload {
  doctors: any[];
  capacity: number;
}

@WebSocketGateway({
  cors: {
    origin: process.env.FRONTEND_URL ?? 'http://localhost:5000',
    credentials: true, // required because frontend uses withCredentials: true
  },
  namespace: '/', // default namespace
})
export class RoomGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server!: Server;

  private readonly logger = new Logger(RoomGateway.name);

  // ─── Lifecycle ────────────────────────────────────────────────────────────

  handleConnection(client: Socket) {
    this.logger.log(`Client connected: ${client.id}`);
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected: ${client.id}`);
  }

  // ─── Room join/leave ──────────────────────────────────────────────────────

  @SubscribeMessage('join-room')
  handleJoinRoom(
    @MessageBody() data: { roomId: number },
    @ConnectedSocket() client: Socket,
  ) {
    const room = `room:${data.roomId}`;
    client.join(room);
    this.logger.log(`Client ${client.id} joined ${room}`);
  }

  @SubscribeMessage('leave-room')
  handleLeaveRoom(
    @MessageBody() data: { roomId: number },
    @ConnectedSocket() client: Socket,
  ) {
    const room = `room:${data.roomId}`;
    client.leave(room);
    this.logger.log(`Client ${client.id} left ${room}`);
  }

  // ─── Emit methods (called from RoomService / VisitService) ───────────────

  /**
    * Called after: callPatient, completeVisitRoom, skipPatient
    * Frontend useRoomSocket listens to this event to update queue
   */
  emitQueueUpdated(roomId: number, payload: QueueUpdatedPayload) {
    this.server
      .to(`room:${roomId}`)
      .emit(`room:${roomId}:queue-updated`, {
        roomId,
        waiting: payload.waiting,
        current: payload.current,
      });
  }

  /**
    * Called after: checkIn, checkOut
    * Frontend useRoomSocket listens to this event to update doctor list
   */
  emitDoctorsUpdated(roomId: number, payload: DoctorsUpdatedPayload) {
    this.server
      .to(`room:${roomId}`)
      .emit(`room:${roomId}:doctors-updated`, {
        roomId,
        doctors: payload.doctors,
        capacity: payload.capacity,
      });
  }
}