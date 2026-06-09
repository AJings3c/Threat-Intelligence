import { useEffect, useMemo, useState } from 'react';
import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge as FlowEdge,
  type Node as FlowNode,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { Language, Severity } from '../types';
import { SEVERITY_COLORS } from '../constants';

export type GraphViewMode = 'graph' | 'list';

export type GraphNodeKind =
  | 'indicator'
  | 'source'
  | 'evidence'
  | 'scenario'
  | 'action'
  | 'asset'
  | 'flow'
  | 'control'
  | 'status';

export interface GraphNode {
  id: string;
  label: string;
  subLabel?: string;
  kind: GraphNodeKind;
  severity?: Severity;
}

export interface GraphColumn {
  id: string;
  title: string;
  nodeIds: string[];
}

export interface GraphEdge {
  from: string;
  to: string;
  label?: string;
  dashed?: boolean;
}

const KIND_STYLE: Record<GraphNodeKind, { accent: string; bg: string; text: string }> = {
  indicator: { accent: '#7dd3fc', bg: '#0d2433', text: '#dff6ff' },
  source: { accent: '#34d399', bg: '#10241d', text: '#d1fae5' },
  evidence: { accent: '#a78bfa', bg: '#211b35', text: '#ede9fe' },
  scenario: { accent: '#fb923c', bg: '#2b1d14', text: '#ffedd5' },
  action: { accent: '#60a5fa', bg: '#11213a', text: '#dbeafe' },
  asset: { accent: '#94a3b8', bg: '#172033', text: '#e2e8f0' },
  flow: { accent: '#2dd4bf', bg: '#10292b', text: '#ccfbf1' },
  control: { accent: '#cbd5e1', bg: '#1f2430', text: '#f8fafc' },
  status: { accent: '#64748b', bg: '#231f2e', text: '#e2e8f0' },
};

const KIND_LABEL: Record<Language, Record<GraphNodeKind, string>> = {
  en: {
    indicator: 'Indicator',
    source: 'Source',
    evidence: 'Evidence',
    scenario: 'Scenario',
    action: 'Action',
    asset: 'Asset',
    flow: 'Flow',
    control: 'Control',
    status: 'Status',
  },
  zh: {
    indicator: '指标',
    source: '来源',
    evidence: '证据',
    scenario: '场景',
    action: '动作',
    asset: '资产',
    flow: '流向',
    control: '控制',
    status: '状态',
  },
};

const COLUMN_GAP = 280;
const ROW_GAP = 118;

const GRAPH_TEXT: Record<Language, Record<string, string>> = {
  en: {
    graph: 'Graph',
    list: 'List',
    nodes: 'Nodes',
    edges: 'Edges',
    selectedNode: 'Selected node',
    adjacencyList: 'Adjacency list',
    noDirectEdges: 'No direct edges.',
    noGraphEdges: 'No graph edges available.',
    selectNode: 'Select a graph node to inspect its evidence path.',
  },
  zh: {
    graph: '图谱',
    list: '列表',
    nodes: '节点',
    edges: '关系',
    selectedNode: '选中节点',
    adjacencyList: '邻接列表',
    noDirectEdges: '暂无直接关系。',
    noGraphEdges: '暂无图关系。',
    selectNode: '选择图节点查看证据路径。',
  },
};

function compact(value: string, max = 74): string {
  return value.length > max ? `${value.slice(0, max - 14)}...${value.slice(-10)}` : value;
}

function nodeAccent(node: GraphNode): string {
  if (node.severity) return SEVERITY_COLORS[node.severity];
  return KIND_STYLE[node.kind].accent;
}

function flowNodeLabel(node: GraphNode, lang: Language) {
  const style = KIND_STYLE[node.kind];
  return (
    <div className="min-w-[190px] max-w-[220px] overflow-hidden rounded-lg">
      <div className="flex items-center gap-2">
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: nodeAccent(node) }} />
        <span className="truncate text-[11px] font-semibold uppercase text-slate-400">{KIND_LABEL[lang][node.kind]}</span>
        {node.severity && (
          <span
            className="ml-auto rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase"
            style={{ borderColor: `${SEVERITY_COLORS[node.severity]}66`, color: SEVERITY_COLORS[node.severity] }}
          >
            {node.severity}
          </span>
        )}
      </div>
      <div className="mt-2 break-words text-[12px] font-semibold leading-5" style={{ color: style.text }}>
        {compact(node.label)}
      </div>
      {node.subLabel && <div className="mt-1 break-words text-[11px] leading-4 text-slate-400">{compact(node.subLabel)}</div>}
    </div>
  );
}

function buildFlowNodes(nodes: GraphNode[], columns: GraphColumn[], lang: Language): FlowNode[] {
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  return columns.flatMap((column, columnIndex) =>
    column.nodeIds
      .map((nodeId, rowIndex) => {
        const node = nodeMap.get(nodeId);
        if (!node) return null;
        const accent = nodeAccent(node);
        const style = KIND_STYLE[node.kind];
        return {
          id: node.id,
          position: { x: columnIndex * COLUMN_GAP, y: rowIndex * ROW_GAP },
          data: { label: flowNodeLabel(node, lang) },
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
          style: {
            width: 226,
            minHeight: 82,
            padding: 12,
            borderColor: `${accent}aa`,
            borderLeft: `4px solid ${accent}`,
            background: `linear-gradient(180deg, rgba(255,255,255,0.035), transparent), ${style.bg}`,
          },
        } satisfies FlowNode;
      })
      .filter(Boolean) as FlowNode[],
  );
}

function buildFlowEdges(edges: GraphEdge[]): FlowEdge[] {
  return edges.map((edge, index) => ({
    id: `${edge.from}-${edge.to}-${index}`,
    source: edge.from,
    target: edge.to,
    label: edge.label,
    type: 'smoothstep',
    animated: edge.dashed,
    markerEnd: { type: MarkerType.ArrowClosed, color: '#64748b' },
    style: {
      stroke: edge.dashed ? '#94a3b8' : '#64748b',
      strokeDasharray: edge.dashed ? '6 6' : undefined,
      strokeWidth: 1.8,
    },
    labelStyle: { fill: '#94a3b8', fontSize: 11, fontWeight: 600 },
    labelBgPadding: [6, 4],
    labelBgBorderRadius: 6,
    labelBgStyle: { fill: '#111827', fillOpacity: 0.88 },
  }));
}

export function GraphDiagram({
  title,
  nodes,
  edges,
  columns,
  lang = 'en',
}: {
  title: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  columns: GraphColumn[];
  lang?: Language;
}) {
  const [mode, setMode] = useState<GraphViewMode>('graph');
  const [selectedId, setSelectedId] = useState(nodes[0]?.id ?? null);
  const nodeMap = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const flowNodes = useMemo(() => buildFlowNodes(nodes, columns, lang), [nodes, columns, lang]);
  const flowEdges = useMemo(() => buildFlowEdges(edges), [edges]);
  const selectedNode = selectedId ? nodeMap.get(selectedId) ?? null : null;
  const text = GRAPH_TEXT[lang];

  useEffect(() => {
    if (!selectedId || !nodeMap.has(selectedId)) setSelectedId(nodes[0]?.id ?? null);
  }, [nodeMap, nodes, selectedId]);

  return (
    <section className="surface overflow-hidden rounded-lg">
      <div className="flex flex-col gap-3 border-b border-line/60 px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="section-title">{title}</h2>
          <p className="section-kicker">
            {nodes.length.toLocaleString()} {text.nodes} / {edges.length.toLocaleString()} {text.edges}
          </p>
        </div>
        <div className="flex rounded-lg border border-line/70 bg-panel-2/80 p-1" role="tablist" aria-label={`${title} view`}>
          {(['graph', 'list'] as GraphViewMode[]).map((item) => (
            <button
              key={item}
              type="button"
              role="tab"
              aria-selected={mode === item}
              onClick={() => setMode(item)}
              className={`min-h-9 rounded-md px-3 text-xs font-semibold transition ${
                mode === item ? 'bg-teal-300/15 text-teal-100' : 'text-slate-400 hover:bg-white/5 hover:text-slate-100'
              }`}
            >
              {item === 'graph' ? text.graph : text.list}
            </button>
          ))}
        </div>
      </div>

      {mode === 'graph' ? (
        <div className="grid min-h-[420px] gap-0 lg:grid-cols-[minmax(0,1fr)_300px]">
          <div className="graph-canvas h-[420px] border-b border-line/50 lg:border-b-0 lg:border-r">
            <ReactFlow
              nodes={flowNodes}
              edges={flowEdges}
              fitView
              fitViewOptions={{ padding: 0.16 }}
              minZoom={0.35}
              maxZoom={1.6}
              nodesDraggable
              nodesConnectable={false}
              elementsSelectable
              onNodeClick={(_, node) => setSelectedId(node.id)}
              proOptions={{ hideAttribution: true }}
            >
              <Background color="#334155" gap={24} size={1} />
              <Controls position="bottom-left" showInteractive={false} />
              <MiniMap
                pannable
                zoomable
                bgColor="#111827"
                maskColor="rgba(7, 10, 16, 0.72)"
                style={{ width: 150, height: 104 }}
                nodeColor={(node) => {
                  const graphNode = nodeMap.get(node.id);
                  return graphNode ? nodeAccent(graphNode) : '#64748b';
                }}
              />
            </ReactFlow>
          </div>
          <aside className="bg-panel/65 p-4">
            <div className="text-xs font-semibold uppercase text-slate-500">{text.selectedNode}</div>
            {selectedNode ? (
              <div className="mt-3 space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="status-dot" style={{ background: nodeAccent(selectedNode) }} />
                  <span className="rounded border border-line/70 px-2 py-1 text-[11px] font-semibold uppercase text-slate-300">
                    {KIND_LABEL[lang][selectedNode.kind]}
                  </span>
                  {selectedNode.severity && (
                    <span className="rounded border px-2 py-1 text-[11px] font-bold uppercase" style={{ borderColor: `${SEVERITY_COLORS[selectedNode.severity]}66`, color: SEVERITY_COLORS[selectedNode.severity] }}>
                      {selectedNode.severity}
                    </span>
                  )}
                </div>
                <div className="break-words text-sm font-semibold leading-6 text-slate-100">{selectedNode.label}</div>
                {selectedNode.subLabel && <div className="break-words text-xs leading-5 text-slate-400">{selectedNode.subLabel}</div>}
                <div>
                  <div className="mb-2 text-xs font-semibold uppercase text-slate-500">{text.edges}</div>
                  <div className="space-y-2">
                    {edges
                      .filter((edge) => edge.from === selectedNode.id || edge.to === selectedNode.id)
                      .slice(0, 10)
                      .map((edge, index) => (
                        <div key={`${edge.from}-${edge.to}-${index}`} className="rounded border border-line/60 bg-panel-2/70 px-2 py-2 text-xs text-slate-400">
                          <span className="font-mono text-slate-300">{nodeMap.get(edge.from)?.label ?? edge.from}</span>
                          <span className="px-1 text-slate-600">{'->'}</span>
                          <span className="font-mono text-slate-300">{nodeMap.get(edge.to)?.label ?? edge.to}</span>
                        </div>
                      ))}
                    {edges.filter((edge) => edge.from === selectedNode.id || edge.to === selectedNode.id).length === 0 && (
                      <div className="text-xs text-slate-500">{text.noDirectEdges}</div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="mt-3 text-sm text-slate-500">{text.selectNode}</div>
            )}
          </aside>
        </div>
      ) : (
        <div className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div className="border-b border-line/50 lg:border-b-0 lg:border-r">
            <div className="border-b border-line/50 px-4 py-2 text-xs font-semibold uppercase text-slate-500">{text.nodes}</div>
            <div className="max-h-[420px] overflow-auto">
              {nodes.map((node) => (
                <button
                  key={node.id}
                  type="button"
                  onClick={() => setSelectedId(node.id)}
                  className={`block w-full border-b border-line/40 px-4 py-3 text-left transition hover:bg-white/[0.04] ${
                    selectedId === node.id ? 'bg-teal-300/10' : ''
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="status-dot" style={{ background: nodeAccent(node) }} />
                    <span className="text-xs font-semibold uppercase text-slate-500">{KIND_LABEL[lang][node.kind]}</span>
                    {node.severity && <span className="text-xs font-bold uppercase" style={{ color: SEVERITY_COLORS[node.severity] }}>{node.severity}</span>}
                  </div>
                  <div className="mt-1 break-words text-sm font-semibold text-slate-100">{node.label}</div>
                  {node.subLabel && <div className="mt-1 break-words text-xs text-slate-500">{node.subLabel}</div>}
                </button>
              ))}
            </div>
          </div>
          <div>
            <div className="border-b border-line/50 px-4 py-2 text-xs font-semibold uppercase text-slate-500">{text.adjacencyList}</div>
            <div className="max-h-[420px] overflow-auto">
              {edges.map((edge, index) => (
                <div key={`${edge.from}-${edge.to}-${index}`} className="grid gap-2 border-b border-line/40 px-4 py-3 text-xs md:grid-cols-[1fr_auto_1fr] md:items-center">
                  <span className="break-words font-mono text-slate-300">{nodeMap.get(edge.from)?.label ?? edge.from}</span>
                  <span className="text-slate-600">{'->'}</span>
                  <span className="break-words font-mono text-slate-300">{nodeMap.get(edge.to)?.label ?? edge.to}</span>
                  {edge.label && <span className="md:col-span-3 text-slate-500">{edge.label}</span>}
                </div>
              ))}
              {edges.length === 0 && <div className="px-4 py-10 text-center text-sm text-slate-500">{text.noGraphEdges}</div>}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
