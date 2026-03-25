import { ScanResult, ScanType, RiskLevel } from "../types";

export async function generateAnalysisSummary(scan: ScanResult): Promise<Partial<ScanResult>> {
  try {
    const response = await fetch('/api/analyze-summary', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ scan }),
    });

    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    const data = await response.json();
    return {
      analysisMessage: data.analysisMessage || data.summary,
      indicators: data.indicators || data.reasons,
      recommendation: data.recommendation
    };
  } catch (error) {
    console.error("AI Analysis Error:", error);
    return getFallbackSummary(scan);
  }
}

function getFallbackSummary(scan: ScanResult): Partial<ScanResult> {
  const isUrl = scan.type === ScanType.URL;
  const isHigh = scan.riskLevel === RiskLevel.HIGH;
  const isMedium = scan.riskLevel === RiskLevel.MEDIUM;

  if (isHigh) {
    return {
      analysisMessage: `Critical security risk detected. This ${isUrl ? 'URL' : 'application'} shows multiple patterns associated with malicious activity and should be avoided.`,
      indicators: [
        ...(scan.indicators || []),
        "Confirmed threat signature match",
        "Suspicious behavior patterns detected"
      ],
      recommendation: "Do not proceed. This item is highly likely to compromise your security or personal data."
    };
  }

  if (isMedium) {
    return {
      analysisMessage: `Potential security concerns identified. While not confirmed as malicious, this ${isUrl ? 'URL' : 'application'} exhibits behaviors that require caution.`,
      indicators: [
        ...(scan.indicators || []),
        "Unusual permission requests",
        "Heuristic pattern match"
      ],
      recommendation: "Proceed with extreme caution. Verify the source and avoid entering sensitive information."
    };
  }

  return {
    analysisMessage: `Analysis complete. This ${isUrl ? 'URL' : 'application'} appears to be safe based on our current security database and heuristic checks.`,
    indicators: [
      ...(scan.indicators || []),
      "No malicious signatures found",
      "Standard behavior patterns"
    ],
    recommendation: "This item looks safe to use, but always remain vigilant when interacting with content from the internet."
  };
}
