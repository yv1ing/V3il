import mermaid from "mermaid";
import { memo, useEffect, useId, useMemo, useState } from "react";

mermaid.initialize({
  startOnLoad: false,
  securityLevel: "strict",
  theme: "base",
  suppressErrorRendering: true,
  themeVariables: {
    primaryColor: "#0d252d",
    primaryTextColor: "#edf7f8",
    primaryBorderColor: "#49c9d8",
    lineColor: "#77e4ed",
    secondaryColor: "#122a3b",
    tertiaryColor: "#10171d",
    noteBkgColor: "#302718",
    noteTextColor: "#fff4d7",
  },
});

export const MermaidDiagram = memo(function MermaidDiagram({ source }: { source: string }) {
  const reactId = useId();
  const renderId = useMemo(() => `mermaid-${reactId.replace(/[^a-zA-Z0-9_-]/g, "")}`, [reactId]);
  const [result, setResult] = useState<{ svg: string } | { error: string } | null>(null);

  useEffect(() => {
    let canceled = false;
    setResult(null);
    mermaid.render(renderId, source).then(({ svg }) => {
      if (!canceled) setResult({ svg });
    }).catch((error: unknown) => {
      if (!canceled) setResult({ error: error instanceof Error ? error.message : String(error) });
    });
    return () => { canceled = true; };
  }, [renderId, source]);

  if (result && "error" in result) {
    return (
      <div className="mermaid-diagram mermaid-diagram-error" title={result.error}>
        <div className="mermaid-error-label">Mermaid render failed</div>
        <pre><code className="language-mermaid">{source}</code></pre>
      </div>
    );
  }

  return (
    <div
      className="mermaid-diagram"
      aria-busy={!result}
      aria-label="Mermaid diagram"
      dangerouslySetInnerHTML={result && "svg" in result ? { __html: result.svg } : undefined}
    />
  );
});
