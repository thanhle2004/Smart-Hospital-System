"use client";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

interface DeleteRoomTypeDialogProps {
  open: boolean;
  roomTypeName: string;
  roomCount?: number;
  onCancel: () => void;
  onConfirm: () => void;
  isDeleting?: boolean;
}

export function DeleteRoomTypeDialog({
  open,
  roomTypeName,
  roomCount,
  onCancel,
  onConfirm,
  isDeleting = false,
}: DeleteRoomTypeDialogProps) {
  const hasRooms = roomCount != null && roomCount > 0;

  return (
    <AlertDialog open={open} onOpenChange={(v) => !v && onCancel()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete Room Type</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2">
              <p>
                Are you sure you want to delete{" "}
                <span className="font-medium text-foreground">
                  {roomTypeName}
                </span>
                ? This action cannot be undone.
              </p>
              {hasRooms && (
                <p className="text-destructive text-sm font-medium">
                  Warning: this room type is used by {roomCount} room
                  {roomCount! > 1 ? "s" : ""}. Deleting it may cause issues.
                </p>
              )}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={onCancel} disabled={isDeleting}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={onConfirm}
            disabled={isDeleting}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {isDeleting ? "Deleting..." : "Delete"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}