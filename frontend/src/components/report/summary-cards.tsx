import { Card, CardContent } from "@/components/ui/card";
import type { Scan } from "@/types/scan";

interface SummaryCardsProps {
  readonly scan: Scan;
}

const SEVERITY_CARDS = [
  { key: "critical_count", label: "Critical", color: "text-red-600" },
  { key: "high_count", label: "High", color: "text-orange-500" },
  { key: "medium_count", label: "Medium", color: "text-yellow-500" },
  { key: "low_count", label: "Low", color: "text-blue-500" },
  { key: "info_count", label: "Info", color: "text-muted-foreground" },
] as const;

export function SummaryCards({ scan }: SummaryCardsProps) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
      <Card>
        <CardContent className="pt-4 text-center">
          <p className="text-3xl font-bold">{scan.total_findings}</p>
          <p className="text-xs text-muted-foreground">Total</p>
        </CardContent>
      </Card>

      {SEVERITY_CARDS.map(({ key, label, color }) => (
        <Card key={key}>
          <CardContent className="pt-4 text-center">
            <p className={`text-3xl font-bold ${color}`}>
              {scan[key]}
            </p>
            <p className="text-xs text-muted-foreground">{label}</p>
          </CardContent>
        </Card>
      ))}

      {scan.agent_safety_grade && (
        <Card>
          <CardContent className="pt-4 text-center">
            <p className="text-3xl font-bold text-primary">
              {scan.agent_safety_grade}
            </p>
            <p className="text-xs text-muted-foreground">Agent Safety</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
