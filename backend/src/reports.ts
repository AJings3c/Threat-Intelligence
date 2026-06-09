import type { ArchitectureThreatModel, IocInvestigation, Language } from './types.js';

function bullet(items: string[]): string {
  return items.map((item) => `- ${item}`).join('\n');
}

function cell(value: string | number | null | undefined): string {
  return String(value ?? '').replace(/\|/g, '\\|').replace(/\n/g, '<br>');
}

function table(headers: string[], rows: Array<Array<string | number | null | undefined>>): string {
  return [
    `| ${headers.map(cell).join(' | ')} |`,
    `| ${headers.map(() => '---').join(' | ')} |`,
    ...rows.map((row) => `| ${row.map(cell).join(' | ')} |`),
  ].join('\n');
}

function csv(items: string[] | undefined): string {
  return items && items.length > 0 ? items.join(', ') : '-';
}

export function investigationMarkdown(result: IocInvestigation, language: Language = 'en'): string {
  const zh = language === 'zh';
  const lines = [
    `# ${zh ? 'IOC 威胁模型' : 'IOC Threat Model'}: ${result.indicator}`,
    '',
    `- ${zh ? '类型' : 'Type'}: ${result.indicatorType}`,
    `- ${zh ? '态势' : 'Posture'}: ${result.model.posture}`,
    `- ${zh ? '最高严重性' : 'Highest severity'}: ${result.model.highestSeverity ?? (zh ? '无' : 'none')}`,
    `- ${zh ? '置信度' : 'Confidence'}: ${result.model.confidence || 0}`,
    `- ${zh ? '精确命中' : 'Exact matches'}: ${result.exactMatches.length}`,
    `- ${zh ? '关联指标' : 'Related indicators'}: ${result.relatedIndicators.length}`,
    '',
    `## ${zh ? '来源汇总' : 'Source Summary'}`,
    result.sourceSummary.length > 0
      ? result.sourceSummary.map((item) => `- ${item.source}: ${item.count}`).join('\n')
      : zh ? '- 本地暂无来源证据' : '- No local source evidence',
    '',
    `## ${zh ? 'STRIDE 场景' : 'STRIDE Scenarios'}`,
    ...result.model.scenarios.flatMap((scenario) => [
      '',
      `### ${scenario.stride}: ${scenario.title}`,
      '',
      `- ${zh ? '严重性' : 'Severity'}: ${scenario.severity}`,
      `- ${zh ? '置信度' : 'Confidence'}: ${scenario.confidence || 0}`,
      '',
      zh ? '证据：' : 'Evidence:',
      bullet(scenario.evidence),
      '',
      zh ? '建议控制措施：' : 'Recommended controls:',
      bullet(scenario.recommendations),
    ]),
    '',
    `## ${zh ? '下一步' : 'Next Steps'}`,
    bullet(result.model.nextSteps),
    '',
  ];
  return lines.join('\n');
}

export function architectureThreatModelMarkdown(model: ArchitectureThreatModel, language: Language = 'en'): string {
  const zh = language === 'zh';
  const strideHeaders = ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'];
  return [
    `# ${zh ? '架构威胁模型' : 'Architecture Threat Model'}: ${model.scope}`,
    '',
    `${zh ? '生成时间' : 'Generated'}: ${model.generatedAt}`,
    '',
    `## ${zh ? '方法论' : 'Methodology'}`,
    '',
    `- ${zh ? '框架' : 'Framework'}: ${model.methodology.framework}`,
    `- ${zh ? '评分' : 'Scoring'}: ${model.methodology.scoring}`,
    '',
    zh ? '流程：' : 'Process:',
    bullet(model.methodology.process),
    '',
    zh ? '触发复评：' : 'Review triggers:',
    bullet(model.methodology.reviewTriggers),
    '',
    zh ? '参考：' : 'References:',
    bullet(model.methodology.references.map((reference) => `${reference.title}: ${reference.url}`)),
    '',
    `## ${zh ? 'DFD 分层' : 'DFD Layers'}`,
    table(
      [zh ? '层级' : 'Layer', zh ? '描述' : 'Description', zh ? '资产' : 'Assets', zh ? '入口点' : 'Entry points'],
      model.layers.map((layer) => [layer.layer, layer.description, csv(layer.assets), csv(layer.entryPoints)]),
    ),
    '',
    `## ${zh ? '资产' : 'Assets'}`,
    table(
      [
        zh ? 'ID' : 'ID',
        zh ? '资产' : 'Asset',
        zh ? '类型' : 'Kind',
        zh ? '信任区' : 'Trust zone',
        zh ? '关键性' : 'Criticality',
        zh ? '数据' : 'Data',
        zh ? '负责人' : 'Owner',
      ],
      model.assets.map((asset) => [
        asset.id,
        asset.name,
        asset.kind,
        asset.trustZone,
        asset.criticality,
        asset.data.join(', '),
        asset.owner ?? '-',
      ]),
    ),
    '',
    `## ${zh ? '信任边界' : 'Trust Boundaries'}`,
    table(
      [zh ? 'ID' : 'ID', zh ? '边界' : 'Boundary', zh ? '描述' : 'Description', zh ? '资产' : 'Assets'],
      model.trustBoundaries.map((boundary) => [boundary.id, boundary.name, boundary.description, boundary.assets.join(', ')]),
    ),
    '',
    `## ${zh ? '数据流' : 'Data Flows'}`,
    table(
      [
        zh ? 'ID' : 'ID',
        zh ? '数据流' : 'Flow',
        zh ? '方向' : 'Direction',
        zh ? '协议' : 'Protocol',
        zh ? '跨边界' : 'Crosses boundary',
        zh ? '攻击面' : 'Threat surface',
      ],
      model.dataFlows.map((flow) => [
        flow.id,
        flow.name,
        `${flow.from} -> ${flow.to}`,
        flow.protocol,
        flow.crossesTrustBoundary ? (zh ? '是' : 'yes') : (zh ? '否' : 'no'),
        csv(flow.threatSurface),
      ]),
    ),
    '',
    `## ${zh ? 'STRIDE 矩阵' : 'STRIDE Matrix'}`,
    table(
      [zh ? '元素' : 'Element', zh ? '优先级' : 'Priority', ...strideHeaders],
      model.threatMatrix.map((row) => [
        `${row.elementName} (${row.elementId})`,
        row.priority,
        ...strideHeaders.map((category) => csv(row.stride[category as keyof typeof row.stride])),
      ]),
    ),
    '',
    `## ${zh ? 'STRIDE 场景' : 'STRIDE Scenarios'}`,
    ...model.scenarios.flatMap((scenario) => [
      '',
      `### ${scenario.stride}: ${scenario.title}`,
      '',
      `- ${zh ? '严重性' : 'Severity'}: ${scenario.severity}`,
      `- ${zh ? '置信度' : 'Confidence'}: ${scenario.confidence || 0}`,
      scenario.dread
        ? `- DREAD: ${scenario.dread.total}/50 (${zh ? '平均' : 'avg'} ${scenario.dread.average}, ${zh ? '风险' : 'risk'} ${scenario.dread.risk})`
        : '',
      scenario.treatment ? `- ${zh ? '处置' : 'Treatment'}: ${scenario.treatment}` : '',
      scenario.assetIds ? `- ${zh ? '影响资产' : 'Assets'}: ${scenario.assetIds.join(', ')}` : '',
      scenario.dataFlowIds ? `- ${zh ? '相关数据流' : 'Data flows'}: ${scenario.dataFlowIds.join(', ')}` : '',
      scenario.threat ? `- ${zh ? '威胁' : 'Threat'}: ${scenario.threat}` : '',
      scenario.impact ? `- ${zh ? '影响' : 'Impact'}: ${scenario.impact}` : '',
      '',
      zh ? '证据：' : 'Evidence:',
      bullet(scenario.evidence),
      ...(scenario.dread
        ? [
            '',
            'DREAD:',
            table(
              [
                zh ? '损害' : 'Damage',
                zh ? '可复现' : 'Reproducibility',
                zh ? '可利用' : 'Exploitability',
                zh ? '影响用户' : 'Affected users',
                zh ? '可发现' : 'Discoverability',
              ],
              [[scenario.dread.damage, scenario.dread.reproducibility, scenario.dread.exploitability, scenario.dread.affectedUsers, scenario.dread.discoverability]],
            ),
            bullet(scenario.dread.rationale),
          ]
        : []),
      '',
      zh ? '建议控制措施：' : 'Recommended controls:',
      bullet(scenario.recommendations),
      ...(scenario.controls
        ? [
            '',
            zh ? '控制项：' : 'Controls:',
            bullet(scenario.controls),
          ]
        : []),
      ...(scenario.verification
        ? [
            '',
            zh ? '验证：' : 'Verification:',
            bullet(scenario.verification),
          ]
        : []),
    ]),
    '',
    `## ${zh ? '攻击路径' : 'Attack Paths'}`,
    table(
      [
        zh ? 'ID' : 'ID',
        zh ? '攻击者' : 'Actor',
        zh ? '目标' : 'Objective',
        zh ? '入口' : 'Entry',
        zh ? '路径' : 'Path',
        zh ? '严重性' : 'Severity',
        zh ? '缓解' : 'Mitigations',
      ],
      model.attackPaths.map((path) => [
        path.id,
        path.actor,
        path.objective,
        path.entryPoint,
        path.path.join(' -> '),
        path.severity,
        path.mitigations.join(', '),
      ]),
    ),
    '',
    `## ${zh ? '控制项追踪' : 'Control Tracking'}`,
    table(
      [
        zh ? 'ID' : 'ID',
        zh ? '控制项' : 'Control',
        zh ? '状态' : 'Status',
        zh ? '负责人' : 'Owner',
        zh ? '关联场景' : 'Scenarios',
        zh ? '验证' : 'Verification',
      ],
      model.controls.map((control) => [
        control.id,
        control.name,
        control.status,
        control.owner,
        control.scenarios.join(', '),
        control.verification.join('; '),
      ]),
    ),
    '',
    `## ${zh ? '假设' : 'Assumptions'}`,
    bullet(model.assumptions),
    '',
    `## ${zh ? '下一步' : 'Next Steps'}`,
    bullet(model.nextSteps),
    '',
  ].join('\n');
}
