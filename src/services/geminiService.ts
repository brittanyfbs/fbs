import { GoogleGenAI } from "@google/genai";
import { ScanResult, ScanType } from "../types";

export async function generateAnalysisSummary(scan: ScanResult): Promise<Partial<ScanResult>> {
  try {
    const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });
    
    const prompt = `
      You are a cybersecurity assistant that explains ${scan.type} scan results in a clear, human-friendly way.
      Your task is to generate natural, user-friendly explanations for ${scan.type} security analysis.

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

      ---
      ## OUTPUT REQUIREMENTS
      Generate 3 parts in JSON format:
      1. summary (1–2 sentences): Clear explanation of the risk level. Natural human tone (no "it").
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
      model: "gemini-3-flash-preview",
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
  } catch (error) {
    console.error("Gemini Analysis Error:", error);
    return {
      analysisMessage: scan.analysisMessage,
      indicators: scan.indicators,
      recommendation: scan.recommendation
    };
  }
}
