"use client";

import { useEffect, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  CreatePriorityRuleDto,
  PriorityRule,
  PriorityRuleFormValues,
  UpdatePriorityRuleDto,
} from "../types/priority-rule.type";

interface PatientTypeLite {
  id: number;
  name: string;
  code: string;
}

interface PriorityRuleFormModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (dto: CreatePriorityRuleDto | UpdatePriorityRuleDto) => Promise<boolean>;
  editingRule?: PriorityRule | null;
  patientTypes: PatientTypeLite[];
  isSubmitting?: boolean;
}

const defaultValues: PriorityRuleFormValues = {
  ruleName: "",
  minAge: "",
  maxAge: "",
  patientTypeId: "",
  isEmergency: false,
  priorityValue: "",
  applyOrder: "0",
  isActive: true,
};

function ruleToFormValues(rule: PriorityRule): PriorityRuleFormValues {
  return {
    ruleName: rule.ruleName,
    minAge: rule.minAge != null ? String(rule.minAge) : "",
    maxAge: rule.maxAge != null ? String(rule.maxAge) : "",
    patientTypeId: rule.patientTypeId != null ? String(rule.patientTypeId) : "",
    isEmergency: rule.isEmergency,
    priorityValue: String(rule.priorityValue),
    applyOrder: String(rule.applyOrder),
    isActive: rule.isActive,
  };
}

function formValuesToDto(
  values: PriorityRuleFormValues
): CreatePriorityRuleDto {
  return {
    ruleName: values.ruleName.trim(),
    minAge: values.minAge !== "" ? Number(values.minAge) : undefined,
    maxAge: values.maxAge !== "" ? Number(values.maxAge) : undefined,
    patientTypeId:
      values.patientTypeId !== "" ? Number(values.patientTypeId) : undefined,
    isEmergency: values.isEmergency,
    priorityValue: Number(values.priorityValue),
    applyOrder: values.applyOrder !== "" ? Number(values.applyOrder) : 0,
    isActive: values.isActive,
  };
}

export function PriorityRuleFormModal({
  open,
  onClose,
  onSubmit,
  editingRule,
  patientTypes,
  isSubmitting = false,
}: PriorityRuleFormModalProps) {
  const [values, setValues] = useState<PriorityRuleFormValues>(defaultValues);
  const [errors, setErrors] = useState<Partial<Record<keyof PriorityRuleFormValues, string>>>({});

  const isEdit = !!editingRule;

  useEffect(() => {
    if (open) {
      setValues(editingRule ? ruleToFormValues(editingRule) : defaultValues);
      setErrors({});
    }
  }, [open, editingRule]);

  const set = (field: keyof PriorityRuleFormValues, value: string | boolean) => {
    setValues((prev) => ({ ...prev, [field]: value }));
    setErrors((prev) => ({ ...prev, [field]: undefined }));
  };

  const validate = (): boolean => {
    const newErrors: typeof errors = {};

    if (!values.ruleName.trim()) {
      newErrors.ruleName = "Rule name is required";
    }
    if (!values.priorityValue || Number(values.priorityValue) <= 0) {
      newErrors.priorityValue = "Priority value must be a positive number";
    }
    if (
      values.minAge !== "" &&
      values.maxAge !== "" &&
      Number(values.minAge) > Number(values.maxAge)
    ) {
      newErrors.maxAge = "Max age must be greater than or equal to min age";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    if (!validate()) return;
    const dto = formValuesToDto(values);
    const ok = await onSubmit(dto);
    if (ok) onClose();
  };

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-[540px]">
        <DialogHeader>
          <DialogTitle>
            {isEdit ? "Edit Priority Rule" : "Add Priority Rule"}
          </DialogTitle>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          {/* Rule Name */}
          <div className="grid gap-1.5">
            <Label htmlFor="ruleName">
              Rule Name <span className="text-destructive">*</span>
            </Label>
            <Input
              id="ruleName"
              placeholder="e.g. Senior Emergency"
              value={values.ruleName}
              onChange={(e) => set("ruleName", e.target.value)}
            />
            {errors.ruleName && (
              <p className="text-xs text-destructive">{errors.ruleName}</p>
            )}
          </div>

          {/* Priority Value & Apply Order */}
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-1.5">
              <Label htmlFor="priorityValue">
                Priority Value <span className="text-destructive">*</span>
              </Label>
              <Input
                id="priorityValue"
                type="number"
                min={1}
                placeholder="e.g. 100"
                value={values.priorityValue}
                onChange={(e) => set("priorityValue", e.target.value)}
              />
              {errors.priorityValue && (
                <p className="text-xs text-destructive">{errors.priorityValue}</p>
              )}
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="applyOrder">Apply Order</Label>
              <Input
                id="applyOrder"
                type="number"
                min={0}
                placeholder="0"
                value={values.applyOrder}
                onChange={(e) => set("applyOrder", e.target.value)}
              />
            </div>
          </div>

          {/* Min Age & Max Age */}
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-1.5">
              <Label htmlFor="minAge">Min Age</Label>
              <Input
                id="minAge"
                type="number"
                min={0}
                placeholder="Optional"
                value={values.minAge}
                onChange={(e) => set("minAge", e.target.value)}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="maxAge">Max Age</Label>
              <Input
                id="maxAge"
                type="number"
                min={0}
                placeholder="Optional"
                value={values.maxAge}
                onChange={(e) => set("maxAge", e.target.value)}
              />
              {errors.maxAge && (
                <p className="text-xs text-destructive">{errors.maxAge}</p>
              )}
            </div>
          </div>

          {/* Patient Type */}
          <div className="grid gap-1.5">
            <Label>Patient Type</Label>
            <Select
              value={values.patientTypeId}
              onValueChange={(v) => set("patientTypeId", v === "none" ? "" : v)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Any patient type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">Any patient type</SelectItem>
                {patientTypes.map((pt) => (
                  <SelectItem key={pt.id} value={String(pt.id)}>
                    {pt.name} ({pt.code})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Toggles */}
          <div className="grid grid-cols-2 gap-4 pt-1">
            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <Label htmlFor="isEmergency" className="text-sm font-medium">
                  Emergency
                </Label>
                <p className="text-xs text-muted-foreground">
                  Apply to emergency cases
                </p>
              </div>
              <Switch
                id="isEmergency"
                checked={values.isEmergency}
                onCheckedChange={(v) => set("isEmergency", v)}
              />
            </div>

            <div className="flex items-center justify-between rounded-lg border p-3">
              <div>
                <Label htmlFor="isActive" className="text-sm font-medium">
                  Active
                </Label>
                <p className="text-xs text-muted-foreground">
                  Enable this rule
                </p>
              </div>
              <Switch
                id="isActive"
                checked={values.isActive}
                onCheckedChange={(v) => set("isActive", v)}
              />
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={isSubmitting}>
            {isSubmitting
              ? isEdit
                ? "Saving..."
                : "Creating..."
              : isEdit
                ? "Save changes"
                : "Create rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}