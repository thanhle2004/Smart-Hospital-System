"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, Plus, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { PriorityRulesTable } from "@/features/admin/priority-rule/components/PriorityRulesTable";
import { PriorityRuleFormModal } from "@/features/admin/priority-rule/components/PriorityRuleFormModal";
import { DeleteConfirmDialog } from "@/features/admin/priority-rule/components/DeleteConfirmDialog";
import { usePriorityRules } from "@/features/admin/priority-rule/hooks/usePriorityRule";
import { PriorityRule } from "@/features/admin/priority-rule/types/priority-rule.type";
import { CreatePriorityRuleDto, UpdatePriorityRuleDto } from "@/features/admin/priority-rule/types/priority-rule.type";

// TODO: replace with real data fetched from /admin/patient-types
const MOCK_PATIENT_TYPES = [
  { id: 1, name: "General", code: "GEN" },
  { id: 2, name: "Pediatric", code: "PED" },
  { id: 3, name: "Senior", code: "SEN" },
  { id: 4, name: "VIP", code: "VIP" },
];

export default function PriorityRulesPage() {
  const router = useRouter();
  const {
    rules,
    isLoading,
    error,
    refetch,
    createRule,
    updateRule,
    deleteRule,
    toggleActive,
  } = usePriorityRules();

  const [modalOpen, setModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<PriorityRule | null>(null);
  const [deletingRule, setDeletingRule] = useState<PriorityRule | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  const openCreateModal = () => {
    setEditingRule(null);
    setModalOpen(true);
  };

  const openEditModal = (rule: PriorityRule) => {
    setEditingRule(rule);
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setEditingRule(null);
  };

  const handleSubmit = async (dto: CreatePriorityRuleDto | UpdatePriorityRuleDto) => {
    setIsSubmitting(true);
    let ok: boolean;
    if (editingRule) {
      ok = await updateRule(editingRule.id, dto as UpdatePriorityRuleDto);
    } else {
      ok = await createRule(dto as CreatePriorityRuleDto);
    }
    setIsSubmitting(false);
    return ok;
  };

  const handleDeleteConfirm = async () => {
    if (!deletingRule) return;
    setIsDeleting(true);
    await deleteRule(deletingRule.id);
    setIsDeleting(false);
    setDeletingRule(null);
  };

  return (
    <main className="container mx-auto py-8 px-4 md:px-6 lg:px-8 max-w-7xl space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Priority Rules
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Configure rules that determine patient queue priority.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => router.push('/admin/dashboard')} className="hover:bg-black hover:text-white">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Dashboard
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={refetch}
            disabled={isLoading}
            title="Refresh"
            className="hover:bg-black hover:text-white"
          >
            <RefreshCw
              className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
            />
          </Button>
          <Button variant="outline" onClick={openCreateModal} className="gap-2 hover:bg-black hover:text-white">
            <Plus className="h-4 w-4" />
            Add Rule
          </Button>
        </div>
      </div>

      {/* Stats bar */}
      {!isLoading && !error && (
        <div className="flex items-center gap-6">
          <div className="text-sm text-muted-foreground">
            Total:{" "}
            <span className="font-medium text-foreground">{rules.length}</span>
          </div>
          <div className="text-sm text-muted-foreground">
            Active:{" "}
            <span className="font-medium text-green-600">
              {rules.filter((r) => r.isActive).length}
            </span>
          </div>
          <div className="text-sm text-muted-foreground">
            Emergency:{" "}
            <span className="font-medium text-destructive">
              {rules.filter((r) => r.isEmergency).length}
            </span>
          </div>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          {error}{" "}
          <button
            onClick={refetch}
            className="underline underline-offset-2 ml-1"
          >
            Retry
          </button>
        </div>
      )}

      {/* Table / Loading */}
      {isLoading ? (
        <div className="rounded-lg border">
          <div className="p-4 space-y-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        </div>
      ) : (
        <PriorityRulesTable
          rules={rules}
          onEdit={openEditModal}
          onDelete={setDeletingRule}
          onToggleActive={(rule) => toggleActive(rule.id)}
        />
      )}

      {/* Create / Edit Modal */}
      <PriorityRuleFormModal
        open={modalOpen}
        onClose={closeModal}
        onSubmit={handleSubmit}
        editingRule={editingRule}
        patientTypes={MOCK_PATIENT_TYPES}
        isSubmitting={isSubmitting}
      />

      {/* Delete Confirm */}
      <DeleteConfirmDialog
        open={!!deletingRule}
        ruleName={deletingRule?.ruleName ?? ""}
        onCancel={() => setDeletingRule(null)}
        onConfirm={handleDeleteConfirm}
        isDeleting={isDeleting}
      />
    </main>
  );
}