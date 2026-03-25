import { GoogleGenAI } from "@google/genai";
import { ScanResult, ScanType, RiskLevel } from "../types";

export async function generateAnalysisSummary(scan: ScanResult): Promise<Partial<ScanResult>> {
  try {
    const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });
    
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
      ## INPUT
      * ${scan.type === ScanType.APK ? 'APK filename' : 'URL'}: ${scan.target}
      * riskLevel: ${scan.riskLevel}
      * detected indicators: ${scan.indicators.join(", ")}
      ${scan.type === ScanType.APK ? `* permissions: ${scan.permissions?.map(p => p.name).join(", ")}` : ""}
      ${scan.permissionAnalysis ? `* permission analysis: ${scan.permissionAnalysis.join(", ")}` : ""}

      ---
      ## OUTPUT REQUIREMENTS
      Generate 3 parts in JSON format:
      1. summary (1–2 sentences): Clear explanation of the risk level. Natural human tone (no "it"). Mention if VirusTotal flagged it.
      2. reasons (bullet points): Explain why the ${scan.type} is flagged. Use simple language.
      3. recommendation: Provide a neutral security recommendation in VERY SIMPLE ENGLISH. DO NOT explicitly tell the user to "install", "open", or "use" the file/link. Instead, state the findings and let the user make the final decision. Use easy words that anyone can understand. For example, "This looks okay, but always be careful with things from the internet."

      ---
      ## STYLE GUIDELINES
      LOW RISK: Tone: neutral and informative. Example: "This ${scan.type === ScanType.APK ? 'app' : 'link'} appears safe based on our analysis. No malicious patterns or unusual ${scan.type === ScanType.APK ? 'permissions' : 'domain behaviors'} were detected."
      MEDIUM RISK: Tone: cautious. Example: "Some aspects of this ${scan.type === ScanType.APK ? 'app' : 'link'} look unusual. Certain ${scan.type === ScanType.APK ? 'permissions or naming patterns' : 'parts of the link'} may not fully match its expected function. Exercise caution."
      HIGH RISK: Tone: warning. Example: "This ${scan.type === ScanType.APK ? 'app' : 'link'} is likely dangerous. The ${scan.type === ScanType.APK ? 'requested permissions are highly sensitive' : 'URL imitates a trusted service'} and could be used for malicious purposes. Proceeding is not recommended."

      ${scan.type === ScanType.APK ? `
      ---
      ## REASONING HINTS (FOR AI)
      Use simple explanations based on:
      * Dangerous permissions (e.g., SMS, microphone, contacts)
      * Permission mismatch (e.g., calculator requesting SMS)
      * Suspicious naming (e.g., bank, login, mod, hack)
      * Potential malicious behavior (data access, background activity)
      ` : ''}

      ---
      ## EXAMPLE OUTPUT FORMAT
      {
        "summary": "...",
        "reasons": ["...", "..."],
        "recommendation": "..."
      }
    `;

    const response = await ai.models.generateContent({
      model: "gemini-3.1-pro-preview",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
      }
    });

    const result = JSON.parse(response.text || "{}");
    return {
      analysisMessage: result.summary || scan.analysisMessage,
      indicators: result.reasons || scan.indicators,
      recommendation: result.recommendation || scan.recommendation
    };
  } catch (error: any) {
    console.error("Gemini Analysis Error:", error);
    
    // Check for quota error (429) or resource exhaustion
    const isQuotaError = 
      error?.message?.includes("429") || 
      error?.message?.includes("RESOURCE_EXHAUSTED") ||
      error?.error?.code === 429 ||
      error?.status === "RESOURCE_EXHAUSTED" ||
      (typeof error === 'string' && (error.includes("429") || error.includes("RESOURCE_EXHAUSTED")));

    if (isQuotaError) {
      return getFallbackSummary(scan);
    }

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
