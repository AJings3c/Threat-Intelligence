import type { ArchitectureThreatModel, IocInvestigation } from './types.js';

function bullet(items: string[]): string {
  return items.map((item) => `- ${item}`).join('\n');
}

export function investigationMarkdown(result: IocInvestigation): string {
  const lines = [
    `# IOC Threat Model: ${result.indicator}`,
    '',
    `- Type: ${result.indicatorType}`,
    `- Posture: ${result.model.posture}`,
    `- Highest severity: ${result.model.highestSeverity ?? 'none'}`,
    `- Confidence: ${result.model.confidence || 0}`,
    `- Exact matches: ${result.exactMatches.length}`,
    `- Related indicators: ${result.relatedIndicators.length}`,
    '',
    '## Source Summary',
    result.sourceSummary.length > 0
      ? result.sourceSummary.map((item) => `- ${item.source}: ${item.count}`).join('\n')
      : '- No local source evidence',
    '',
    '## STRIDE Scenarios',
    ...result.model.scenarios.flatMap((scenario) => [
      '',
      `### ${scenario.stride}: ${scenario.title}`,
      '',
      `- Severity: ${scenario.severity}`,
      `- Confidence: ${scenario.confidence || 0}`,
      '',
      'Evidence:',
      bullet(scenario.evidence),
      '',
      'Recommended controls:',
      bullet(scenario.recommendations),
    ]),
    '',
    '## Next Steps',
    bullet(result.model.nextSteps),
    '',
  ];
  return lines.join('\n');
}

export function architectureThreatModelMarkdown(model: ArchitectureThreatModel): string {
  return [
    `# Architecture Threat Model: ${model.scope}`,
    '',
    `Generated: ${model.generatedAt}`,
    '',
    '## Assets',
    model.assets
      .map((asset) => `- ${asset.name} (${asset.kind}, ${asset.trustZone}, ${asset.criticality}): ${asset.data.join(', ')}`)
      .join('\n'),
    '',
    '## Trust Boundaries',
    model.trustBoundaries.map((boundary) => `- ${boundary.name}: ${boundary.description}`).join('\n'),
    '',
    '## Data Flows',
    model.dataFlows
      .map(
        (flow) =>
          `- ${flow.name}: ${flow.from} -> ${flow.to} over ${flow.protocol}${
            flow.crossesTrustBoundary ? ' (crosses trust boundary)' : ''
          }`,
      )
      .join('\n'),
    '',
    '## STRIDE Scenarios',
    ...model.scenarios.flatMap((scenario) => [
      '',
      `### ${scenario.stride}: ${scenario.title}`,
      '',
      `- Severity: ${scenario.severity}`,
      `- Confidence: ${scenario.confidence || 0}`,
      '',
      'Evidence:',
      bullet(scenario.evidence),
      '',
      'Recommended controls:',
      bullet(scenario.recommendations),
    ]),
    '',
    '## Assumptions',
    bullet(model.assumptions),
    '',
    '## Next Steps',
    bullet(model.nextSteps),
    '',
  ].join('\n');
}
