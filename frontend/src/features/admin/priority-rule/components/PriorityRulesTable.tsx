"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { MoreHorizontal, Pencil, Trash2 } from "lucide-react";
import { PriorityRule } from "../types/priority-rule.type";
import { Switch } from "@/components/ui/switch";

interface PriorityRulesTableProps {
  rules: PriorityRule[];
  onEdit: (rule: PriorityRule) => void;
  onDelete: (rule: PriorityRule) => void;
  onToggleActive: (rule: PriorityRule) => void;
  isToggling?: string | number | null;
}

function AgeRange({ min, max }: { min?: number | null; max?: number | null }) {
  if (min == null && max == null) return <span className="text-muted-foreground">—</span>;
  if (min != null && max != null) return <span>{min} – {max}</span>;
  if (min != null) return <span>≥ {min}</span>;
  return <span>≤ {max}</span>;
}

export function PriorityRulesTable({
  rules,
  onEdit,
  onDelete,
  onToggleActive,
  isToggling,
}: PriorityRulesTableProps) {
  if (rules.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <p className="text-muted-foreground text-sm">No priority rules found.</p>
        <p className="text-muted-foreground text-xs mt-1">
          Click &quot;Add Rule&quot; to create one.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[40px]">#</TableHead>
            <TableHead>Rule Name</TableHead>
            <TableHead>Priority Value</TableHead>
            <TableHead>Apply Order</TableHead>
            <TableHead>Age Range</TableHead>
            <TableHead>Patient Type</TableHead>
            <TableHead>Emergency</TableHead>
            <TableHead className="w-[100px]">Status</TableHead>
            <TableHead className="w-[60px]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.map((rule, index) => (
            <TableRow key={rule.id}>
              <TableCell className="text-muted-foreground text-xs">{index + 1}</TableCell>
              <TableCell className="font-medium">{rule.ruleName}</TableCell>
              <TableCell>
                <span className="font-semibold tabular-nums">{rule.priorityValue}</span>
              </TableCell>
              <TableCell className="tabular-nums">{rule.applyOrder}</TableCell>
              <TableCell><AgeRange min={rule.minAge} max={rule.maxAge} /></TableCell>
              <TableCell>
                {rule.patientType?.name ? (
                  <Badge variant="outline">{rule.patientType.name}</Badge>
                ) : (
                  <span className="text-muted-foreground">Any</span>
                )}
              </TableCell>
              <TableCell>
                {rule.isEmergency ? (
                  <Badge variant="destructive">Emergency</Badge>
                ) : (
                  <span className="text-muted-foreground">—</span>
                )}
              </TableCell>
              <TableCell>
                <Switch
                  checked={rule.isActive}
                  disabled={isToggling === rule.id}
                  onCheckedChange={() => onToggleActive(rule)}
                  aria-label="Toggle status"
                />
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
                    <DropdownMenuItem onClick={() => onEdit(rule)}>
                      <Pencil className="mr-2 h-4 w-4" /> Edit
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      onClick={() => onDelete(rule)}
                      className="text-destructive focus:text-destructive"
                    >
                      <Trash2 className="mr-2 h-4 w-4" /> Delete
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