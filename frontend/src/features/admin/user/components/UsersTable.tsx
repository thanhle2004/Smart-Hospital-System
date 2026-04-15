'use client';

import { format } from 'date-fns';
import { vi } from 'date-fns/locale';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Button } from '@/components/ui/button';
import { MoreHorizontal, Pencil, Trash2, PowerOff } from 'lucide-react';
import { UserStatusBadge, UserRoleBadge } from './UserBadges';
import type { User } from '../types/user.type';

interface UserTableProps {
  users: User[];
  onEdit: (user: User) => void;
  onDelete: (user: User) => void;
  onDeactivate: (user: User) => void;
}

export function UserTable({
  users,
  onEdit,
  onDelete,
  onDeactivate,
}: UserTableProps) {
  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[60px]">#</TableHead>
            <TableHead className="w-[220px]">Full Name</TableHead>
            <TableHead>Email</TableHead>
            <TableHead className="w-[100px]">Role</TableHead>
            <TableHead className="w-[110px]">Status</TableHead>
            <TableHead className="w-[160px]">Last Login</TableHead>
            <TableHead className="w-[60px]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {users.length === 0 && (
            <TableRow>
              <TableCell
                colSpan={7}
                className="h-24 text-center text-muted-foreground"
              >
                No users found.
              </TableCell>
            </TableRow>
          )}
          {users.map((user, index) => (
            <TableRow key={user.id}>
              <TableCell className="text-muted-foreground text-sm tabular-nums">
                {index + 1}
              </TableCell>
              <TableCell className="font-medium">
                {user.profile?.fullName ?? (
                  <span className="italic text-muted-foreground">Not updated</span>
                )}
              </TableCell>
              <TableCell>{user.email}</TableCell>
              <TableCell>
                <UserRoleBadge role={user.role} />
              </TableCell>
              <TableCell>
                <UserStatusBadge isActive={user.isActive} />
              </TableCell>
              <TableCell className="text-sm text-muted-foreground">
                {user.lastLoginAt
                  ? format(new Date(user.lastLoginAt), 'dd/MM/yyyy HH:mm', {
                      locale: vi,
                    })
                  : '—'}
              </TableCell>
              <TableCell>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon" className="h-8 w-8">
                      <MoreHorizontal className="h-4 w-4" />
                      <span className="sr-only">Open menu</span>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuLabel>Action</DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={() => onEdit(user)}>
                      <Pencil className="mr-2 h-4 w-4" />
                      Edit
                    </DropdownMenuItem>
                    {user.isActive && (
                      <DropdownMenuItem onClick={() => onDeactivate(user)}>
                        <PowerOff className="mr-2 h-4 w-4" />
                        Deactivate
                      </DropdownMenuItem>
                    )}
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      onClick={() => onDelete(user)}
                      className="text-destructive focus:text-destructive"
                    >
                      <Trash2 className="mr-2 h-4 w-4" />
                      Delete User
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}