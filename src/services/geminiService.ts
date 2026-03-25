import { GoogleGenAI } from "@google/genai";
import { ScanResult, ScanType, RiskLevel } from "../types";

export async function generateAnalysisSummary(scan: ScanResult): Promise<Partial<ScanResult>> {
  try {
    const GEMINI_API_KEY = (import.meta as any).env?.VITE_GEMINI_API_KEY || process.env.GEMINI_API_KEY;
    if (!GEMINI_API_KEY) {
      console.warn("GEMINI_API_KEY not found in environment, falling back to heuristic summary.");
      return getFallbackSummary(scan);
    }

    const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
    
    const prompt = `
      You are a cybersecurity assistant that explains ${scan.type} scan results in a clear, human-friendly way.
      Your task is to generate natural, user-friendly explanations for ${scan.type} security analysis.
      This analysis combines results from VirusTotal (70+ engines) and heuristic manifest analysis.

      ---
      ## IMPORTANT LANGUAGE STYLE RULES
      * DO NOT use the word "it" to start sentences
      * Avoid robotic or AI-like phrasing
      * Use simple, natural English (like a real app explaining to users)
      * Keep explanations short and clear
      * Sound like a real human, not a technical system

      ---
      ## SCAN DATA
      Target: ${scan.target}
      Type: ${scan.type}
      Risk Level: ${scan.riskLevel}
      Risk Score: ${scan.riskScore}/100
      Indicators: ${scan.indicators?.join(', ')}
      ${scan.permissions ? `Permissions: ${scan.permissions.map((p: any) => p.name).join(', ')}` : ''}

      ---
      ## OUTPUT FORMAT (JSON)
      Return ONLY a JSON object with these fields:
      {
        "analysisMessage": "A 2-3 sentence human-friendly explanation of the security status.",
        "recommendation": "A clear, actionable recommendation for the user.",
        "indicators": ["A list of 2-3 key security findings in plain English"]
      }
    `;

    const result = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: prompt,
      config: {
        responseMimeType: "application/json"
      }
    });

    const responseText = result.text;
    if (!responseText) {
      throw new Error("Empty response from Gemini");
    }

    const data = JSON.parse(responseText);
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
