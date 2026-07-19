import type { ReactNode } from 'react';
import {
  MarkerType,
  Position,
  type Edge as FlowEdge,
  type Node as FlowNode,
} from '@xyflow/react';
import type { KnowledgeEntity, KnowledgeGraph, Language } from '../../types';
import { TYPE_COLOR, TYPE_LABEL } from './shared';

export function graphElements(graph: KnowledgeGraph, lang: Language): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const adjacency = new Map<string, string[]>();
  for (const relationship of graph.relationships) {
    adjacency.set(relationship.sourceRef, [...(adjacency.get(relationship.sourceRef) ?? []), relationship.targetRef]);
    adjacency.set(relationship.targetRef, [...(adjacency.get(relationship.targetRef) ?? []), relationship.sourceRef]);
  }

  const levelById = new Map<string, number>([[graph.rootId, 0]]);
  let frontier = [graph.rootId];
  while (frontier.length > 0) {
    const next: string[] = [];
    for (const id of frontier) {
      const level = levelById.get(id) ?? 0;
      for (const neighbor of adjacency.get(id) ?? []) {
        if (levelById.has(neighbor)) continue;
        levelById.set(neighbor, level + 1);
        next.push(neighbor);
      }
    }
    frontier = next;
  }

  const maxLevel = Math.max(0, ...levelById.values());
  const rowsByLevel = new Map<number, KnowledgeEntity[]>();
  for (const entity of graph.entities) {
    const level = levelById.get(entity.id) ?? maxLevel + 1;
    rowsByLevel.set(level, [...(rowsByLevel.get(level) ?? []), entity]);
  }

  const nodes: FlowNode[] = [];
  for (const [level, entities] of rowsByLevel) {
    entities.sort((first, second) => first.name.localeCompare(second.name));
    const columnHeight = (entities.length - 1) * 116;
    entities.forEach((entity, index) => {
      const label: ReactNode = (
        <div className="min-w-0 text-left">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: TYPE_COLOR[entity.type] }} />
            <span className="truncate text-[11px] font-semibold text-slate-400">{TYPE_LABEL[lang][entity.type]}</span>
          </div>
          <div className="mt-1.5 line-clamp-2 break-words text-xs font-bold leading-5 text-slate-100">{entity.name}</div>
          <div className="mt-1 text-[10px] font-semibold uppercase text-slate-500">TLP:{entity.tlp}</div>
        </div>
      );
      nodes.push({
        id: entity.id,
        position: { x: level * 270, y: index * 116 - columnHeight / 2 },
        data: { label },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        style: {
          width: 218,
          minHeight: 86,
          padding: 12,
          borderColor: entity.id === graph.rootId ? TYPE_COLOR[entity.type] : `${TYPE_COLOR[entity.type]}99`,
        },
      });
    });
  }

  const edges: FlowEdge[] = graph.relationships.map((relationship) => ({
    id: relationship.id,
    source: relationship.sourceRef,
    target: relationship.targetRef,
    label: relationship.relationshipType,
    type: 'smoothstep',
    markerEnd: { type: MarkerType.ArrowClosed, color: '#64748b' },
    style: { stroke: '#64748b', strokeWidth: 1.6 },
    labelStyle: { fill: '#94a3b8', fontSize: 10, fontWeight: 600 },
    labelBgPadding: [5, 3],
    labelBgBorderRadius: 4,
    labelBgStyle: { fill: '#111827', fillOpacity: 0.9 },
  }));
  return { nodes, edges };
}
