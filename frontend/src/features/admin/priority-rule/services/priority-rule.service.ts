import {
  CreatePriorityRuleDto,
  PriorityRule,
  UpdatePriorityRuleDto,
} from "../types/priority-rule.type";
import { api } from '@/lib/axios';

export const priorityRuleService = {
  async getAll(): Promise<PriorityRule[]> {
    const response = await api.get<PriorityRule[]>('/admin/priority-rules');
    return response.data;
  },

  async getOne(id: number): Promise<PriorityRule> {
    const response = await api.get<PriorityRule>(`/admin/priority-rules/${id}`);
    return response.data;
  },

  async create(dto: CreatePriorityRuleDto): Promise<PriorityRule> {
    const response = await api.post<PriorityRule>('/admin/priority-rules', dto);
    return response.data;
  },

  async update(id: number, dto: UpdatePriorityRuleDto): Promise<PriorityRule> {
    const response = await api.patch<PriorityRule>(`/admin/priority-rules/${id}`, dto);
    return response.data;
  },

  async remove(id: number): Promise<void> {
    await api.delete<void>(`/admin/priority-rules/${id}`);
  },

  async toggleActive(id: number): Promise<PriorityRule> {
    const response = await api.patch<PriorityRule>(`/admin/priority-rules/${id}/toggle-active`);
    return response.data;
  },
};