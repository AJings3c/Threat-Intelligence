import { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Maximize2, Minimize2, Download } from 'lucide-react';
import type { Language, ThreatIndicator } from '../types';
import { buildProvenanceGraph, type ProvenanceGraphNode } from '../evidence';

type ThreatNode = ProvenanceGraphNode & d3.SimulationNodeDatum;

interface ThreatLink extends d3.SimulationLinkDatum<ThreatNode> {
  source: string | ThreatNode;
  target: string | ThreatNode;
  relation: 'reported_by';
  strength: number;
}

const NETWORK_TEXT = {
  en: {
    title: 'Threat Relationship Network',
    subtitle: 'Interactive IOC relationship visualization',
    fullscreen: 'Fullscreen',
    exitFullscreen: 'Exit Fullscreen',
    export: 'Export PNG',
    refresh: 'Refresh',
    nodes: 'Nodes',
    links: 'Links',
    loading: 'Building network...',
    noData: 'No relationship data available',
  },
  zh: {
    title: '威胁关系网络',
    subtitle: '交互式 IOC 关系可视化',
    fullscreen: '全屏',
    exitFullscreen: '退出全屏',
    export: '导出 PNG',
    refresh: '刷新',
    nodes: '节点',
    links: '链接',
    loading: '构建网络中...',
    noData: '无关系数据',
  },
};

const NODE_COLORS = {
  ip: '#7dd3fc',
  domain: '#34d399',
  url: '#fb923c',
  hash: '#a78bfa',
  cidr: '#60a5fa',
  cve: '#f87171',
  source: '#94a3b8',
};

const SEVERITY_SIZE = {
  critical: 12,
  high: 10,
  medium: 8,
  low: 6,
};

export function ThreatNetworkGraph({ lang, indicators }: { lang: Language; indicators: ThreatIndicator[] }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [stats, setStats] = useState({ nodes: 0, links: 0 });

  const t = NETWORK_TEXT[lang];

  useEffect(() => {
    if (!svgRef.current || indicators.length === 0) {
      setIsLoading(false);
      return;
    }

    setIsLoading(true);

    const container = containerRef.current;
    if (!container) return;

    const width = container.clientWidth;
    const height = container.clientHeight;

    const svg = d3.select<SVGSVGElement, unknown>(svgRef.current);
    svg.selectAll('*').remove();

    const g = svg.append('g');

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform.toString());
      });

    svg.call(zoom);

    const graph = buildProvenanceGraph(indicators);
    const nodes: ThreatNode[] = graph.nodes.map((node) => ({ ...node }));
    const links: ThreatLink[] = graph.edges.map((edge) => ({ ...edge }));

    setStats({ nodes: nodes.length, links: links.length });

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        'link',
        d3
          .forceLink<ThreatNode, ThreatLink>(links)
          .id((d) => d.id)
          .distance(80)
          .strength((d) => d.strength),
      )
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(30));

    const link = g
      .append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#334155')
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.6);

    const drag = d3
      .drag<SVGCircleElement, ThreatNode>()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    const node = g
      .append('g')
      .selectAll<SVGCircleElement, ThreatNode>('circle')
      .data(nodes)
      .join('circle')
      .attr('r', (d) => (d.severity ? SEVERITY_SIZE[d.severity] : 8))
      .attr('fill', (d) => NODE_COLORS[d.type])
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 2)
      .style('cursor', 'pointer')
      .call(drag);

    node
      .append('title')
      .text((d) =>
        d.type === 'source'
          ? `${d.label}\nThreat intelligence source`
          : `${d.label}\n${d.type} | ${d.severity}\nConfidence: ${d.confidence}%`,
      );

    simulation.on('tick', () => {
      link
        .attr('x1', (d) => (d.source as ThreatNode).x ?? 0)
        .attr('y1', (d) => (d.source as ThreatNode).y ?? 0)
        .attr('x2', (d) => (d.target as ThreatNode).x ?? 0)
        .attr('y2', (d) => (d.target as ThreatNode).y ?? 0);

      node.attr('cx', (d) => d.x ?? 0).attr('cy', (d) => d.y ?? 0);
    });

    setIsLoading(false);

    return () => {
      simulation.stop();
    };
  }, [indicators]);

  const toggleFullscreen = () => {
    if (!containerRef.current) return;

    if (!isFullscreen) {
      containerRef.current.requestFullscreen().then(() => setIsFullscreen(true));
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false));
    }
  };

  const exportPNG = () => {
    if (!svgRef.current) return;

    const svg = svgRef.current;
    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(svg);
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const img = new Image();
    const svgBlob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(svgBlob);

    img.onload = () => {
      canvas.width = svg.clientWidth;
      canvas.height = svg.clientHeight;
      ctx.fillStyle = '#0f172a';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0);

      canvas.toBlob((blob) => {
        if (!blob) return;
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `threat-network-${Date.now()}.png`;
        a.click();
        URL.revokeObjectURL(url);
      });
    };

    img.src = url;
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4 text-sm text-slate-400">
          <span>
            {stats.nodes} {t.nodes}
          </span>
          <span>
            {stats.links} {t.links}
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={exportPNG}
            className="control inline-flex min-h-11 items-center gap-2 px-3 text-xs"
          >
            <Download className="h-3.5 w-3.5" />
            {t.export}
          </button>
          <button
            type="button"
            onClick={toggleFullscreen}
            className="control inline-flex min-h-11 items-center gap-2 px-3 text-xs"
          >
            {isFullscreen ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
            {isFullscreen ? t.exitFullscreen : t.fullscreen}
          </button>
        </div>
      </div>

      <div ref={containerRef} className="surface relative overflow-hidden rounded-lg" style={{ height: '600px' }}>
        {isLoading ? (
          <div className="flex h-full items-center justify-center">
            <div className="text-center">
              <div className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-teal-200 border-t-transparent" />
              <div className="mt-2 text-sm text-slate-400">{t.loading}</div>
            </div>
          </div>
        ) : indicators.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-slate-400">{t.noData}</div>
        ) : (
          <svg ref={svgRef} width="100%" height="100%" className="bg-slate-950/50" />
        )}
      </div>

      <div className="surface-raised rounded-lg p-3">
        <div className="grid grid-cols-3 gap-3 text-xs md:grid-cols-6">
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <div key={type} className="flex items-center gap-2">
              <div className="h-3 w-3 rounded-full" style={{ backgroundColor: color }} />
              <span className="capitalize text-slate-300">{type}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
