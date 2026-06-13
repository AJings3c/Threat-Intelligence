import { randomUUID } from 'node:crypto';
import {
  createCase as persistCreateCase,
  updateCase as persistUpdateCase,
  getCase as persistGetCase,
  getCases as persistGetCases,
  addCaseIoc,
  getCaseIocs,
  addCaseComment as persistAddCaseComment,
  getCaseComments as persistGetCaseComments,
} from './persist.js';
import type { Case, CaseComment, CaseStatus, Severity } from './types.js';

export interface CreateCaseInput {
  title: string;
  severity: Severity;
  assignee?: string;
}

export interface UpdateCaseInput {
  status?: CaseStatus;
  assignee?: string;
}

export interface AddCommentInput {
  author: string;
  content: string;
}

export function createCase(input: CreateCaseInput): Case {
  const now = Date.now();
  const caseData = {
    id: randomUUID(),
    title: input.title,
    status: 'open' as CaseStatus,
    severity: input.severity,
    assignee: input.assignee,
    createdAt: now,
    updatedAt: now,
  };

  persistCreateCase({
    id: caseData.id,
    title: caseData.title,
    status: caseData.status,
    severity: caseData.severity,
    assignee: caseData.assignee,
    createdAt: caseData.createdAt,
    updatedAt: caseData.updatedAt,
  });

  return {
    ...caseData,
    iocIds: [],
    comments: [],
  };
}

export function updateCase(id: string, input: UpdateCaseInput): Case | null {
  const existing = getCase(id);
  if (!existing) return null;

  const updates = {
    status: input.status,
    assignee: input.assignee,
    updatedAt: Date.now(),
  };

  persistUpdateCase(id, updates);

  return {
    ...existing,
    status: input.status ?? existing.status,
    assignee: input.assignee ?? existing.assignee,
    updatedAt: updates.updatedAt,
  };
}

export function getCase(id: string): Case | null {
  const row = persistGetCase(id) as {
    id: string;
    title: string;
    status: CaseStatus;
    severity: Severity;
    assignee: string | null;
    created_at: number;
    updated_at: number;
  } | null;

  if (!row) return null;

  const iocs = getCaseIocs(id);
  const comments = getCaseComments(id);

  return {
    id: row.id,
    title: row.title,
    status: row.status,
    severity: row.severity,
    assignee: row.assignee ?? undefined,
    iocIds: iocs.map((ioc) => ioc.ioc_id),
    comments,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function listCases(filters?: { status?: CaseStatus; assignee?: string }): Case[] {
  const rows = persistGetCases(filters) as Array<{
    id: string;
    title: string;
    status: CaseStatus;
    severity: Severity;
    assignee: string | null;
    created_at: number;
    updated_at: number;
  }>;

  return rows.map((row) => {
    const iocs = getCaseIocs(row.id);
    const comments = getCaseComments(row.id);

    return {
      id: row.id,
      title: row.title,
      status: row.status,
      severity: row.severity,
      assignee: row.assignee ?? undefined,
      iocIds: iocs.map((ioc) => ioc.ioc_id),
      comments,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  });
}

export function addIocToCase(caseId: string, iocId: string): boolean {
  const existing = getCase(caseId);
  if (!existing) return false;

  addCaseIoc(caseId, iocId, Date.now());
  return true;
}

export function addComment(caseId: string, input: AddCommentInput): CaseComment | null {
  const existing = getCase(caseId);
  if (!existing) return null;

  const comment: CaseComment = {
    id: randomUUID(),
    caseId,
    author: input.author,
    content: input.content,
    createdAt: Date.now(),
  };

  persistAddCaseComment(comment);
  return comment;
}

export function getCaseComments(caseId: string): CaseComment[] {
  const rows = persistGetCaseComments(caseId) as Array<{
    id: string;
    case_id: string;
    author: string;
    content: string;
    created_at: number;
  }>;

  return rows.map((row) => ({
    id: row.id,
    caseId: row.case_id,
    author: row.author,
    content: row.content,
    createdAt: row.created_at,
  }));
}

