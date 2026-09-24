import { useState } from "react";
import { Brain, AlertTriangle, RefreshCw, Loader2, CheckCircle, XCircle, Info } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Skeleton } from "@/components/ui/Skeleton";
import { AiObservation } from "@/components/ai/AiObservation";
import { AiProvenance } from "@/components/ai/AiProvenance";
import { EvidenceChipList } from "@/components/evidence/EvidenceChip";
import type { AIInvestigationAnalysis, AIInvestigateResponse, AIInvestigationEvidenceMeta } from "@/types/api";

interface AiInvestigationPanelProps {
  incidentId: number;
  onInvestigate: () => void;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  data: AIInvestigateResponse | null;
  isIdle: boolean;
  reset: () => void;
}

export function AiInvestigationPanel({
  incidentId,
  onInvestigate,
  isLoading,
  isError,
  error,
  data,
  isIdle,
  reset,
}: AiInvestigationPanelProps) {
  const [showAll, setShowAll] = useState(false);

  const aiError = data?.analysis?.provenance?.provider === "deterministic" && data?.analysis?.provenance?.model === "no-llm";

  if (isIdle) {
    return (
      <Card className="border-amber-700/50 bg-amber-900/10">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Brain className="h-4 w-4 text-amber-400" />
              AI Investigation
            </CardTitle>
            <Badge variant="info" className="text-xs">AI-assisted</Badge>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            AI-assisted analysis of the available investigation evidence. Click to generate.
          </p>
        </CardHeader>
        <CardContent>
          <Button
            onClick={onInvestigate}
            className="w-full sm:w-auto"
            disabled={isLoading}
            aria-busy={isLoading}
          >
            <Brain className="mr-2 h-4 w-4" /> Investigate with AI
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (isLoading) {
    return (
      <Card className="border-amber-700/50 bg-amber-900/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-4 w-4 text-amber-400" />
            AI Investigation
            <Loader2 className="ml-2 h-4 w-4 animate-spin text-amber-400" aria-hidden="true" />
          </CardTitle>
          <p className="text-xs text-slate-400 mt-1">
            Analyzing the available evidence… This may take a few moments.
          </p>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <Skeleton className="h-8 w-3/4" />
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    const isProviderError = error?.message.includes("503") || error?.message.includes("AI provider error");
    const isValidationError = error?.message.includes("502") || error?.message.includes("Invalid AI response");
    const isTimeout = error?.message.includes("timeout");

    let errorTitle = "AI Investigation Failed";
    let errorMessage = error?.message || "An unknown error occurred";
    let errorAction = "Try Again";

    if (isProviderError) {
      if (error?.message.includes("disabled")) {
        errorTitle = "AI Not Configured";
        errorMessage = "No AI provider is configured on the HORUS backend. Set AI_PROVIDER to gemini, groq, or ollama in the backend .env file and restart the backend. The deterministic investigation remains available.";
      } else if (error?.message.includes("authentication")) {
        errorTitle = "AI Authentication Failed";
        errorMessage = "The backend could not authenticate with the AI provider. Check AI_API_KEY (or AI_GROQ_API_KEY for groq) in the backend .env file and restart the backend. The deterministic investigation remains available.";
      } else if (error?.message.includes("model not found")) {
        errorTitle = "AI Model Not Found";
        errorMessage = "The backend could not find the configured AI model on the provider. Check AI_MODEL in the backend .env file (for example gemini-2.5-flash, with no quotes or extra spaces) and restart the backend. The deterministic investigation remains available.";
      } else if (error?.message.includes("timeout")) {
        errorTitle = "AI Request Timed Out";
        errorMessage = "The AI provider took too long to respond. For local models, raise AI_TIMEOUT in the backend .env file and restart the backend. No deterministic investigation data was changed.";
      } else if (error?.message.includes("rate_limit") || error?.message.includes("429")) {
        errorTitle = "AI Rate Limited";
        errorMessage = "The AI provider rate-limited the request. Wait a moment and try again. The deterministic investigation remains available.";
      } else {
        errorTitle = "AI Unavailable";
        errorMessage = "The AI investigation service is currently unavailable. Check the backend terminal for the exact provider error. The deterministic investigation remains available.";
      }
    } else if (isValidationError) {
      errorTitle = "Invalid AI Response";
      errorMessage = "The AI returned an invalid analysis. No AI conclusion was applied to the incident.";
    } else if (isTimeout) {
      errorTitle = "AI Request Timed Out";
      errorMessage = "The AI investigation request timed out. No deterministic investigation data was changed.";
    }

    return (
      <Card className="border-red-700/50 bg-red-900/10">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Brain className="h-4 w-4 text-amber-400" />
              AI Investigation
            </CardTitle>
            <XCircle className="h-4 w-4 text-red-400" />
          </div>
          <p className="text-xs text-slate-400 mt-1">{errorTitle}</p>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="rounded-lg border border-red-700 bg-red-900/30 p-3 text-sm text-red-200">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 flex-shrink-0" />
              <span>{errorMessage}</span>
            </div>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={onInvestigate} disabled={isLoading}>
              <RefreshCw className="mr-2 h-4 w-4" /> {errorAction}
            </Button>
            <Button variant="ghost" size="sm" onClick={reset}>
              Dismiss
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return (
      <Card className="border-amber-700/50 bg-amber-900/10">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-4 w-4 text-amber-400" />
            AI Investigation
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Button onClick={onInvestigate} disabled={isLoading}>
            <Brain className="mr-2 h-4 w-4" /> Investigate with AI
          </Button>
        </CardContent>
      </Card>
    );
  }

  const { analysis, evidence_meta, provenance } = data;

  return (
    <Card className="border-amber-700/50 bg-amber-900/10">
      <CardHeader>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <Brain className="h-4 w-4 text-amber-400" />
            <CardTitle>AI Investigation</CardTitle>
            {aiError ? (
              <Badge variant="info" className="text-xs">Insufficient Evidence</Badge>
            ) : (
              <Badge variant="warning" className="text-xs">AI-assisted</Badge>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={reset}>
              <RefreshCw className="mr-1 h-4 w-4" /> Re-investigate
            </Button>
          </div>
        </div>
        <p className="text-xs text-slate-400">
          {aiError
            ? "Insufficient evidence available for AI investigation: incident contains no alerts or events."
            : "This analysis is generated from the available investigation evidence. Review the cited evidence before making operational decisions."}
        </p>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Summary */}
        <div className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
          <h4 className="text-sm font-semibold text-slate-200 mb-2 flex items-center gap-2">
            <Info className="h-4 w-4 text-sky-400" /> Summary
          </h4>
          <p className="text-sm text-slate-300 whitespace-pre-wrap break-words">{analysis.summary}</p>
        </div>

        {/* Observations */}
        {analysis.observations && analysis.observations.length > 0 && (
          <div className="space-y-3">
            <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Brain className="h-4 w-4 text-amber-400" /> Observations
            </h4>
            <div className="space-y-2">
              {analysis.observations.map((obs, idx) => (
                <AiObservation key={`${obs.type}-${idx}`} observation={obs} />
              ))}
            </div>
          </div>
        )}

        {/* Supporting Evidence */}
        {analysis.supporting_evidence && analysis.supporting_evidence.length > 0 && (
          <div className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
            <h4 className="text-sm font-semibold text-slate-200 mb-2 flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-emerald-400" /> Supporting Evidence
            </h4>
            <EvidenceChipList ids={analysis.supporting_evidence} />
          </div>
        )}

        {/* Alternative Explanations */}
        {analysis.alternative_explanations && analysis.alternative_explanations.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Brain className="h-4 w-4 text-violet-400" /> Alternative Explanations
            </h4>
            <div className="space-y-2">
              {analysis.alternative_explanations.map((alt, idx) => (
                <div key={idx} className="rounded-lg border border-slate-700 bg-slate-800/50 p-3">
                  <p className="text-sm text-slate-300">{alt.explanation}</p>
                  {alt.evidence_ids && alt.evidence_ids.length > 0 && (
                    <div className="mt-2">
                      <span className="text-xs text-slate-400 mr-2">Evidence:</span>
                      <EvidenceChipList ids={alt.evidence_ids} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommended Steps */}
        {analysis.recommended_steps && analysis.recommended_steps.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-emerald-400" /> Recommended Investigation Steps
            </h4>
            <ol className="space-y-1 ml-4 list-decimal text-sm text-slate-300">
              {analysis.recommended_steps.map((step, idx) => (
                <li key={idx} className="whitespace-pre-wrap break-words">{step}</li>
              ))}
            </ol>
          </div>
        )}

        {/* Limitations */}
        {analysis.limitations && analysis.limitations.length > 0 && (
          <div className="rounded-lg border border-amber-700 bg-amber-900/30 p-4">
            <h4 className="text-sm font-semibold text-amber-200 mb-2 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" /> Limitations
            </h4>
            <ul className="space-y-1 ml-4 list-disc text-sm text-amber-300">
              {analysis.limitations.map((lim, idx) => (
                <li key={idx} className="whitespace-pre-wrap break-words">{lim}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Provenance */}
        <AiProvenance provenance={provenance} evidenceMeta={evidence_meta} />
      </CardContent>
    </Card>
  );
}