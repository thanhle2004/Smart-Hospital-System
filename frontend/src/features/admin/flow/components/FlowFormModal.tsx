'use client';

import { useEffect, useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Plus, Trash2, ArrowUpDown } from 'lucide-react';
import { useRoomTypes } from '../hooks/useRoomTypes';
import type {
  Flow,
  FlowRoomItemDto,
  FlowRoomDependencyItemDto,
  FlowFormDto,
} from '../types/flow.type';

// ─── Types ────────────────────────────────────────────────────────────────────

type Mode = 'create' | 'edit';

interface Props {
  open: boolean;
  onClose: () => void;
  onSubmit: (dto: FlowFormDto) => Promise<void>;
  flow?: Flow | null;
  mode: Mode;
}

// ─── Local room row state ─────────────────────────────────────────────────────

interface RoomRow extends FlowRoomItemDto {
  _key: string; // unique key for list rendering
}

interface DepRow extends FlowRoomDependencyItemDto {
  _key: string;
}

let _counter = 0;
const uid = () => String(++_counter);

// ─── Component ────────────────────────────────────────────────────────────────

export function FlowFormModal({ open, onClose, onSubmit, flow, mode }: Props) {
  const { roomTypes, isLoading: loadingRooms } = useRoomTypes();

  const [name, setName] = useState('');
  const [rooms, setRooms] = useState<RoomRow[]>([]);
  const [deps, setDeps] = useState<DepRow[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Populate khi edit
  useEffect(() => {
    if (!open) return;
    if (mode === 'edit' && flow) {
      setName(flow.name);
      setRooms(
        flow.flowRooms.map((r) => ({
          _key: uid(),
          roomTypeId: r.roomTypeId,
          defaultOrder: r.defaultOrder,
        })),
      );
      setDeps(
        (flow.dependencies ?? []).map((d) => ({
          _key: uid(),
          roomTypeId: d.roomTypeId,
          requiredRoomTypeId: d.requiredRoomTypeId,
        })),
      );
    } else {
      setName('');
      setRooms([]);
      setDeps([]);
    }
    setError(null);
  }, [open, mode, flow]);

  // ─── Room helpers ───────────────────────────────────────────────────────────

  const addRoom = () =>
    setRooms((prev) => [
      ...prev,
      { _key: uid(), roomTypeId: 0, defaultOrder: prev.length + 1 },
    ]);

  const removeRoom = (key: string) =>
    setRooms((prev) => prev.filter((r) => r._key !== key));

  const updateRoom = (key: string, patch: Partial<FlowRoomItemDto>) =>
    setRooms((prev) =>
      prev.map((r) => (r._key === key ? { ...r, ...patch } : r)),
    );

  // ─── Dependency helpers ─────────────────────────────────────────────────────

  const addDep = () =>
    setDeps((prev) => [
      ...prev,
      { _key: uid(), roomTypeId: 0, requiredRoomTypeId: 0 },
    ]);

  const removeDep = (key: string) =>
    setDeps((prev) => prev.filter((d) => d._key !== key));

  const updateDep = (key: string, patch: Partial<FlowRoomDependencyItemDto>) =>
    setDeps((prev) =>
      prev.map((d) => (d._key === key ? { ...d, ...patch } : d)),
    );

  // ─── Validation ─────────────────────────────────────────────────────────────

  const validate = (): string | null => {
    if (!name.trim()) return 'Name is required';
    if (rooms.length === 0) return 'At least one room is required';
    if (rooms.some((r) => !r.roomTypeId))
      return 'Please select a room type for all rooms';
    const ids = rooms.map((r) => r.roomTypeId);
    if (new Set(ids).size !== ids.length)
      return 'Room type cannot be duplicated in the flow';
    return null;
  };

  // ─── Submit ─────────────────────────────────────────────────────────────────

  const handleSubmit = async () => {
    const err = validate();
    if (err) { setError(err); return; }

    setSubmitting(true);
    setError(null);
    try {
      const dto: FlowFormDto = {
        name: name.trim(),
        rooms: rooms.map(({ roomTypeId, defaultOrder }) => ({
          roomTypeId,
          defaultOrder,
        })),
        dependencies: deps
          .filter((d) => d.roomTypeId && d.requiredRoomTypeId)
          .map(({ roomTypeId, requiredRoomTypeId }) => ({
            roomTypeId,
            requiredRoomTypeId,
          })),
      };
      await onSubmit(dto);
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'An error occurred. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {mode === 'create' ? 'Create Flow' : 'Edit Flow'}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-6 py-2">
          {/* Name */}
          <div className="space-y-1.5">
            <Label htmlFor="flow-name">Name</Label>
            <Input
              id="flow-name"
              placeholder="E.g., General Checkup Flow"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <Separator />
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-sm font-medium flex items-center gap-2">
                <ArrowUpDown className="w-4 h-4 text-muted-foreground" />
                Rooms in Flow
              </Label>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={addRoom}
                disabled={loadingRooms}
              >
                <Plus className="w-4 h-4 mr-1" />
                Add room
              </Button>
            </div>

            {rooms.length === 0 && (
              <p className="text-sm text-muted-foreground italic">
                No rooms added. Click "Add room" to get started.
              </p>
            )}

            <div className="space-y-2">
              {rooms.map((room, idx) => (
                <div
                  key={room._key}
                  className="flex items-center gap-2 p-2 rounded-md border bg-muted/30"
                >
                  <Badge variant="outline" className="shrink-0 w-7 justify-center">
                    {idx + 1}
                  </Badge>

                  <Select
                    value={room.roomTypeId ? String(room.roomTypeId) : ''}
                    onValueChange={(v) =>
                      updateRoom(room._key, { roomTypeId: Number(v) })
                    }
                  >
                    <SelectTrigger className="flex-1">
                      <SelectValue placeholder="Choose room type..." />
                    </SelectTrigger>
                    <SelectContent>
                      {roomTypes.map((rt) => (
                        <SelectItem key={rt.id} value={String(rt.id)}>
                          {rt.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <Label className="text-xs text-muted-foreground">Order</Label>
                    <Input
                      type="number"
                      min={1}
                      className="w-16 h-8 text-sm"
                      value={room.defaultOrder}
                      onChange={(e) =>
                        updateRoom(room._key, {
                          defaultOrder: Number(e.target.value),
                        })
                      }
                    />
                  </div>

                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="shrink-0 h-8 w-8 text-destructive hover:text-destructive"
                    onClick={() => removeRoom(room._key)}
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              ))}
            </div>
          </div>

          {/* Dependencies */}
          <Separator />
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-sm font-medium">
                Dependencies{' '}
                <span className="text-muted-foreground font-normal">
                  (optional)
                </span>
              </Label>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={addDep}
                disabled={rooms.length < 2}
              >
                <Plus className="w-4 h-4 mr-1" />
                Add Dependency
              </Button>
            </div>

            {deps.length === 0 && (
              <p className="text-sm text-muted-foreground italic">
                No dependencies added.
              </p>
            )}

            <div className="space-y-2">
              {deps.map((dep) => (
                <div
                  key={dep._key}
                  className="flex items-center gap-2 p-2 rounded-md border bg-muted/30"
                >
                  <Select
                    value={dep.roomTypeId ? String(dep.roomTypeId) : ''}
                    onValueChange={(v) =>
                      updateDep(dep._key, { roomTypeId: Number(v) })
                    }
                  >
                    <SelectTrigger className="flex-1">
                      <SelectValue placeholder="This room..." />
                    </SelectTrigger>
                    <SelectContent>
                      {rooms
                        .filter((r) => r.roomTypeId)
                        .map((r) => {
                          const rt = roomTypes.find(
                            (x) => x.id === r.roomTypeId,
                          );
                          return (
                            <SelectItem
                              key={r.roomTypeId}
                              value={String(r.roomTypeId)}
                            >
                              {rt?.name ?? r.roomTypeId}
                            </SelectItem>
                          );
                        })}
                    </SelectContent>
                  </Select>

                  <span className="text-sm text-muted-foreground shrink-0">
                    required
                  </span>

                  <Select
                    value={
                      dep.requiredRoomTypeId
                        ? String(dep.requiredRoomTypeId)
                        : ''
                    }
                    onValueChange={(v) =>
                      updateDep(dep._key, {
                        requiredRoomTypeId: Number(v),
                      })
                    }
                  >
                    <SelectTrigger className="flex-1">
                      <SelectValue placeholder="Required room..." />
                    </SelectTrigger>
                    <SelectContent>
                      {rooms
                        .filter(
                          (r) =>
                            r.roomTypeId && r.roomTypeId !== dep.roomTypeId,
                        )
                        .map((r) => {
                          const rt = roomTypes.find(
                            (x) => x.id === r.roomTypeId,
                          );
                          return (
                            <SelectItem
                              key={r.roomTypeId}
                              value={String(r.roomTypeId)}
                            >
                              {rt?.name ?? r.roomTypeId}
                            </SelectItem>
                          );
                        })}
                    </SelectContent>
                  </Select>

                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="shrink-0 h-8 w-8 text-destructive hover:text-destructive"
                    onClick={() => removeDep(dep._key)}
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              ))}
            </div>
          </div>

          {/* Error */}
          {error && (
            <p className="text-sm text-destructive bg-destructive/10 rounded-md px-3 py-2">
              {error}
            </p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={submitting}>
            {submitting
              ? 'Saving...'
              : mode === 'create'
                ? 'Create Flow'
                : 'Save Changes'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}