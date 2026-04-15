import {
  CreatePriorityRuleDto,
  PriorityRule,
  UpdatePriorityRuleDto,
} from "../types/priority-rule.type";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    credentials: "include",
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error?.message ?? `Request failed: ${res.status}`);
  }

  return res.json();
}

export const priorityRuleService = {
  getAll(): Promise<PriorityRule[]> {
    return request<PriorityRule[]>("/admin/priority-rules");
  },

  getOne(id: number): Promise<PriorityRule> {
    return request<PriorityRule>(`/admin/priority-rules/${id}`);
  },

  create(dto: CreatePriorityRuleDto): Promise<PriorityRule> {
    return request<PriorityRule>("/admin/priority-rules", {
      method: "POST",
      body: JSON.stringify(dto),
    });
  },

  update(id: number, dto: UpdatePriorityRuleDto): Promise<PriorityRule> {
    return request<PriorityRule>(`/admin/priority-rules/${id}`, {
      method: "PATCH",
      body: JSON.stringify(dto),
    });
  },

  remove(id: number): Promise<void> {
    return request<void>(`/admin/priority-rules/${id}`, {
      method: "DELETE",
    });
  },

  toggleActive(id: number): Promise<PriorityRule> {
    return request<PriorityRule>(`/admin/priority-rules/${id}/toggle-active`, {
      method: "PATCH",
    });
  },
};