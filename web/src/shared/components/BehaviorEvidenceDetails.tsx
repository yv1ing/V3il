import { FileJson2 } from "lucide-react";
import type { BehaviorEvent } from "../api/types";


export function BehaviorEvidenceDetails({ event }: { event: BehaviorEvent }) {
  return (
    <details className="behavior-evidence-details">
      <summary><FileJson2 size={14} />Evidence record</summary>
      <pre>{JSON.stringify(event, null, 2)}</pre>
    </details>
  );
}
