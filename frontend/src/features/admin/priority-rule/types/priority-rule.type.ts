export interface PriorityRule {
  id: number;
  ruleName: string;
  minAge?: number | null;
  maxAge?: number | null;
  patientTypeId?: number | null;
  patientType?: {
    id: number;
    name: string;
    code: string;
  } | null;
  isEmergency: boolean;
  priorityValue: number;
  applyOrder: number;
  isActive: boolean;
}

export interface CreatePriorityRuleDto {
  ruleName: string;
  minAge?: number;
  maxAge?: number;
  patientTypeId?: number;
  isEmergency?: boolean;
  priorityValue: number;
  applyOrder?: number;
  isActive?: boolean;
}

export type UpdatePriorityRuleDto = Partial<CreatePriorityRuleDto>;

export interface PriorityRuleFormValues {
  ruleName: string;
  minAge: string;
  maxAge: string;
  patientTypeId: string;
  isEmergency: boolean;
  priorityValue: string;
  applyOrder: string;
  isActive: boolean;
}