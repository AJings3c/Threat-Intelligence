import { useState, useEffect, type FormEvent } from 'react';
import { Plus, Save, Trash2, Power, AlertCircle, Zap, Webhook, Database } from 'lucide-react';
import type { Language, Severity, RuleTriggerType, RuleActionType } from '../types';

interface Rule {
  id: string;
  name: string;
  triggerType: RuleTriggerType;
  triggerConfig: Record<string, unknown>;
  actions: RuleAction[];
  enabled: boolean;
  createdAt: number;
}

interface RuleAction {
  type: RuleActionType;
  config: Record<string, unknown>;
}

const RULE_TEXT = {
  en: {
    title: 'Rules & Automation',
    subtitle: 'Configure automated responses to threat intelligence',
    createRule: 'Create Rule',
    ruleName: 'Rule Name',
    namePlaceholder: 'High-severity IOC webhook',
    triggerType: 'Trigger Type',
    iocMatch: 'IOC Match',
    threshold: 'Threshold',
    schedule: 'Schedule',
    triggerConfig: 'Trigger Configuration',
    severity: 'Severity',
    minConfidence: 'Min Confidence',
    tags: 'Tags (comma-separated)',
    actions: 'Actions',
    addAction: 'Add Action',
    webhook: 'Webhook',
    enrich: 'Auto-Enrich',
    ticket: 'Create Ticket',
    block: 'Block IOC',
    webhookUrl: 'Webhook URL',
    ticketSystem: 'Ticket System',
    save: 'Save Rule',
    saving: 'Saving...',
    cancel: 'Cancel',
    noRules: 'No rules configured',
    enabled: 'Enabled',
    disabled: 'Disabled',
    delete: 'Delete',
    executions: 'Executions',
    viewHistory: 'View History',
    lastTriggered: 'Last Triggered',
    never: 'Never',
  },
  zh: {
    title: '规则与自动化',
    subtitle: '配置威胁情报自动响应',
    createRule: '创建规则',
    ruleName: '规则名称',
    namePlaceholder: '高严重性 IOC Webhook',
    triggerType: '触发类型',
    iocMatch: 'IOC 匹配',
    threshold: '阈值',
    schedule: '定时',
    triggerConfig: '触发配置',
    severity: '严重性',
    minConfidence: '最低置信度',
    tags: '标签（逗号分隔）',
    actions: '动作',
    addAction: '添加动作',
    webhook: 'Webhook',
    enrich: '自动富化',
    ticket: '创建工单',
    block: '阻断 IOC',
    webhookUrl: 'Webhook URL',
    ticketSystem: '工单系统',
    save: '保存规则',
    saving: '保存中...',
    cancel: '取消',
    noRules: '无配置规则',
    enabled: '已启用',
    disabled: '已禁用',
    delete: '删除',
    executions: '执行次数',
    viewHistory: '查看历史',
    lastTriggered: '最近触发',
    never: '从未',
  },
};

export function RuleEditor({ lang }: { lang: Language }) {
  const [rules, setRules] = useState<Rule[]>([]);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [formName, setFormName] = useState('');
  const [formTriggerType, setFormTriggerType] = useState<RuleTriggerType>('ioc_match');
  const [formSeverity, setFormSeverity] = useState<Severity | ''>('');
  const [formMinConfidence, setFormMinConfidence] = useState('');
  const [formTags, setFormTags] = useState('');
  const [formActions, setFormActions] = useState<RuleAction[]>([]);

  const t = RULE_TEXT[lang];

  const loadRules = async () => {
    try {
      const response = await fetch('/api/rules');
      if (!response.ok) throw new Error(`Failed to load rules: ${response.status}`);
      const data = (await response.json()) as { rules: Rule[] };
      setRules(data.rules);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load rules');
    }
  };

  useEffect(() => {
    void loadRules();
  }, []);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);

    try {
      const triggerConfig: Record<string, unknown> = {};
      if (formSeverity) triggerConfig.severity = formSeverity;
      if (formMinConfidence) triggerConfig.minConfidence = Number(formMinConfidence);
      if (formTags) triggerConfig.tags = formTags.split(',').map((t) => t.trim());

      const response = await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formName,
          triggerType: formTriggerType,
          triggerConfig,
          actions: formActions,
          enabled: true,
        }),
      });

      if (!response.ok) throw new Error(`Failed to create rule: ${response.status}`);

      await loadRules();
      setEditing(false);
      setFormName('');
      setFormSeverity('');
      setFormMinConfidence('');
      setFormTags('');
      setFormActions([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save rule');
    } finally {
      setSaving(false);
    }
  };

  const toggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      const response = await fetch(`/api/rules/${ruleId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });

      if (!response.ok) throw new Error(`Failed to update rule: ${response.status}`);
      await loadRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle rule');
    }
  };

  const addAction = (type: RuleActionType) => {
    const config: Record<string, unknown> = {};
    if (type === 'webhook') config.url = '';
    if (type === 'ticket') config.system = 'jira';

    setFormActions([...formActions, { type, config }]);
  };

  const removeAction = (index: number) => {
    setFormActions(formActions.filter((_, i) => i !== index));
  };

  const updateActionConfig = (index: number, key: string, value: unknown) => {
    const updated = [...formActions];
    updated[index] = {
      ...updated[index],
      config: { ...updated[index].config, [key]: value },
    };
    setFormActions(updated);
  };

  return (
    <div className="space-y-5">
      <div className="flex justify-between">
        <div />
        <button
          type="button"
          onClick={() => setEditing(!editing)}
          className="primary-action control inline-flex items-center gap-2 px-4 py-2 text-sm font-bold"
        >
          <Plus className="h-4 w-4" />
          {t.createRule}
        </button>
      </div>

      {error && (
        <div className="flex items-start gap-3 rounded-lg border border-red-400/45 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {editing && (
        <form onSubmit={handleSubmit} className="surface rounded-lg p-4">
          <div className="mb-4">
            <label htmlFor="rule-name" className="mb-2 block text-sm font-semibold text-slate-300">
              {t.ruleName}
            </label>
            <input
              id="rule-name"
              type="text"
              value={formName}
              onChange={(e) => setFormName(e.target.value)}
              placeholder={t.namePlaceholder}
              required
              className="control w-full text-sm"
            />
          </div>

          <div className="mb-4">
            <label className="mb-2 block text-sm font-semibold text-slate-300">{t.triggerType}</label>
            <div className="grid grid-cols-3 gap-2">
              {(['ioc_match', 'threshold', 'schedule'] as RuleTriggerType[]).map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => setFormTriggerType(type)}
                  className={`control px-3 py-2 text-sm ${
                    formTriggerType === type ? 'bg-teal-300/15 text-teal-100' : 'text-slate-300'
                  }`}
                >
                  {type === 'ioc_match' ? t.iocMatch : type === 'threshold' ? t.threshold : t.schedule}
                </button>
              ))}
            </div>
          </div>

          {formTriggerType === 'ioc_match' && (
            <div className="mb-4 space-y-3">
              <div>
                <label className="mb-2 block text-sm font-semibold text-slate-300">{t.severity}</label>
                <select
                  value={formSeverity}
                  onChange={(e) => setFormSeverity(e.target.value as Severity | '')}
                  className="control w-full text-sm"
                >
                  <option value="">Any</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <label className="mb-2 block text-sm font-semibold text-slate-300">{t.minConfidence}</label>
                <input
                  type="number"
                  value={formMinConfidence}
                  onChange={(e) => setFormMinConfidence(e.target.value)}
                  placeholder="0-100"
                  min="0"
                  max="100"
                  className="control w-full text-sm"
                />
              </div>
              <div>
                <label className="mb-2 block text-sm font-semibold text-slate-300">{t.tags}</label>
                <input
                  type="text"
                  value={formTags}
                  onChange={(e) => setFormTags(e.target.value)}
                  placeholder="malware, apt, ransomware"
                  className="control w-full text-sm"
                />
              </div>
            </div>
          )}

          <div className="mb-4">
            <div className="mb-2 flex items-center justify-between">
              <label className="text-sm font-semibold text-slate-300">{t.actions}</label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => addAction('webhook')}
                  className="control inline-flex items-center gap-1.5 px-2 py-1 text-xs"
                >
                  <Webhook className="h-3 w-3" />
                  {t.webhook}
                </button>
                <button
                  type="button"
                  onClick={() => addAction('enrich')}
                  className="control inline-flex items-center gap-1.5 px-2 py-1 text-xs"
                >
                  <Database className="h-3 w-3" />
                  {t.enrich}
                </button>
              </div>
            </div>
            {formActions.length === 0 ? (
              <div className="rounded-lg border border-line/60 bg-panel-2/40 px-4 py-6 text-center text-sm text-slate-400">
                {t.addAction}
              </div>
            ) : (
              <div className="space-y-2">
                {formActions.map((action, index) => (
                  <div key={index} className="surface-raised flex items-center gap-3 rounded-lg p-3">
                    <div className="flex-1">
                      <div className="mb-1 text-xs font-semibold text-slate-400">{action.type}</div>
                      {action.type === 'webhook' && (
                        <input
                          type="url"
                          value={(action.config.url as string) ?? ''}
                          onChange={(e) => updateActionConfig(index, 'url', e.target.value)}
                          placeholder={t.webhookUrl}
                          className="control w-full text-xs"
                        />
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={() => removeAction(index)}
                      className="text-red-300 hover:text-red-100"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="flex gap-2">
            <button
              type="submit"
              disabled={saving || !formName || formActions.length === 0}
              className="primary-action control inline-flex items-center gap-2 px-4 py-2 text-sm font-bold disabled:opacity-50"
            >
              <Save className="h-4 w-4" />
              {saving ? t.saving : t.save}
            </button>
            <button
              type="button"
              onClick={() => setEditing(false)}
              className="control px-4 py-2 text-sm"
            >
              {t.cancel}
            </button>
          </div>
        </form>
      )}

      <div className="surface rounded-lg p-4">
        {rules.length === 0 ? (
          <div className="py-8 text-center text-sm text-slate-400">{t.noRules}</div>
        ) : (
          <div className="space-y-3">
            {rules.map((rule) => (
              <div key={rule.id} className="surface-raised rounded-lg p-3">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="mb-1 flex items-center gap-2">
                      <Zap className="h-4 w-4 text-teal-200" />
                      <h4 className="font-semibold text-slate-100">{rule.name}</h4>
                    </div>
                    <div className="text-xs text-slate-400">
                      {rule.triggerType} • {rule.actions.length} {t.actions}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => toggleRule(rule.id, !rule.enabled)}
                      className={`inline-flex items-center gap-1.5 rounded px-2 py-1 text-xs font-semibold ${
                        rule.enabled
                          ? 'bg-emerald-300/15 text-emerald-100'
                          : 'bg-slate-500/15 text-slate-400'
                      }`}
                    >
                      <Power className="h-3 w-3" />
                      {rule.enabled ? t.enabled : t.disabled}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
