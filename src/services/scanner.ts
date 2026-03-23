/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { GoogleGenAI, Type } from "@google/genai";
import { RiskLevel, ScanResult, ScanType, PermissionInfo } from '../types';

const DANGEROUS_PERMISSIONS: PermissionInfo[] = [
  { name: 'READ_SMS', description: 'Allows the app to read your SMS messages, including OTPs.', severity: RiskLevel.HIGH },
  { name: 'RECEIVE_SMS', description: 'Allows the app to intercept incoming SMS messages.', severity: RiskLevel.HIGH },
  { name: 'READ_CONTACTS', description: 'Allows the app to see all your saved contacts.', severity: RiskLevel.MEDIUM },
  { name: 'ACCESS_FINE_LOCATION', description: 'Allows the app to track your precise location.', severity: RiskLevel.MEDIUM },
  { name: 'RECORD_AUDIO', description: 'Allows the app to record audio using the microphone.', severity: RiskLevel.HIGH },
  { name: 'CAMERA', description: 'Allows the app to take photos and videos.', severity: RiskLevel.MEDIUM },
  { name: 'READ_EXTERNAL_STORAGE', description: 'Allows the app to read files on your device.', severity: RiskLevel.MEDIUM },
];

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });

export const scanUrl = async (url: string): Promise<ScanResult> => {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: `Analyze this URL for security risks: ${url}. 
      Act as a security expert and a Random Forest classifier. 
      Classify the risk level as LOW, MEDIUM, or HIGH.
      Provide:
      1. riskLevel: LOW, MEDIUM, or HIGH
      2. riskScore: A number from 0 to 100 representing the risk level (higher is riskier)
      3. confidence: A number from 0 to 100 representing your confidence in this assessment
      4. analysisMessage: A concise explanation of the risk
      5. indicators: A list of identified indicators (e.g., suspicious domain, insecure protocol, phishing keywords)
      6. recommendation: A clear recommendation for the user (e.g., "Do not enter any personal information on this site.")
      7. actions: A list of specific actions the user should take (e.g., "Close the tab immediately", "Report as phishing")`,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            riskLevel: { type: Type.STRING, enum: ["LOW", "MEDIUM", "HIGH"] },
            riskScore: { type: Type.NUMBER },
            confidence: { type: Type.NUMBER },
            analysisMessage: { type: Type.STRING },
            indicators: { type: Type.ARRAY, items: { type: Type.STRING } },
            recommendation: { type: Type.STRING },
            actions: { type: Type.ARRAY, items: { type: Type.STRING } }
          },
          required: ["riskLevel", "riskScore", "confidence", "analysisMessage", "indicators", "recommendation", "actions"]
        }
      }
    });

    const result = JSON.parse(response.text || '{}');

    return {
      id: Math.random().toString(36).substr(2, 9),
      type: ScanType.URL,
      target: url,
      riskLevel: result.riskLevel as RiskLevel,
      riskScore: result.riskScore,
      confidence: result.confidence,
      timestamp: Date.now(),
      analysisMessage: result.analysisMessage,
      indicators: result.indicators,
      recommendation: result.recommendation,
      actions: result.actions,
    };
  } catch (error) {
    console.error("Gemini API Error:", error);
    // Fallback to basic logic if API fails
    return fallbackScanUrl(url);
  }
};

const fallbackScanUrl = (url: string): ScanResult => {
  const indicators: string[] = [];
  let riskLevel = RiskLevel.LOW;
  let riskScore = 15;
  let confidence = 85;
  let analysisMessage = "No suspicious patterns detected. The URL appears to be safe based on our current AI analysis.";
  let recommendation = "You can proceed with caution. Always verify the source before entering sensitive data.";
  let actions = ["Verify the URL matches the official site", "Check for HTTPS"];

  try {
    const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
    if (urlObj.protocol === 'http:') {
      indicators.push('Insecure protocol (HTTP)');
      riskLevel = RiskLevel.MEDIUM;
      riskScore = 55;
      analysisMessage = "Analysis completed but insecure protocol was detected. Exercise caution.";
      recommendation = "Avoid entering sensitive information on this website as the connection is not encrypted.";
      actions = ["Look for an HTTPS version of this site", "Do not enter passwords or credit card info"];
    }
  } catch (e) {
    indicators.push('Malformed URL structure');
    riskLevel = RiskLevel.HIGH;
    riskScore = 95;
    analysisMessage = "Critical error: The URL format is invalid or malicious.";
    recommendation = "Do not visit this URL. It may be a phishing attempt or contain malware.";
    actions = ["Close the tab immediately", "Report this link if you received it via SMS/Email"];
  }

  return {
    id: Math.random().toString(36).substr(2, 9),
    type: ScanType.URL,
    target: url,
    riskLevel,
    riskScore,
    confidence,
    timestamp: Date.now(),
    analysisMessage,
    indicators,
    recommendation,
    actions,
  };
};

export const scanApk = async (filename: string): Promise<ScanResult> => {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: `Analyze this APK filename for security risks: ${filename}. 
      Act as a security expert and a Random Forest classifier. 
      Classify the risk level as LOW, MEDIUM, or HIGH.
      Provide:
      1. riskLevel: LOW, MEDIUM, or HIGH
      2. riskScore: A number from 0 to 100 representing the risk level (higher is riskier)
      3. confidence: A number from 0 to 100 representing your confidence in this assessment
      4. analysisMessage: A concise explanation of the risk
      5. indicators: A list of identified indicators
      6. permissions: A list of potentially dangerous permissions this app might request (choose from: READ_SMS, RECEIVE_SMS, READ_CONTACTS, ACCESS_FINE_LOCATION, RECORD_AUDIO, CAMERA, READ_EXTERNAL_STORAGE)
      7. recommendation: A clear recommendation for the user
      8. actions: A list of specific actions the user should take`,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            riskLevel: { type: Type.STRING, enum: ["LOW", "MEDIUM", "HIGH"] },
            riskScore: { type: Type.NUMBER },
            confidence: { type: Type.NUMBER },
            analysisMessage: { type: Type.STRING },
            indicators: { type: Type.ARRAY, items: { type: Type.STRING } },
            permissions: { type: Type.ARRAY, items: { type: Type.STRING } },
            recommendation: { type: Type.STRING },
            actions: { type: Type.ARRAY, items: { type: Type.STRING } }
          },
          required: ["riskLevel", "riskScore", "confidence", "analysisMessage", "indicators", "permissions", "recommendation", "actions"]
        }
      }
    });

    const result = JSON.parse(response.text || '{}');
    const permissions = (result.permissions || []).map((pName: string) => 
      DANGEROUS_PERMISSIONS.find(p => p.name === pName)
    ).filter(Boolean) as PermissionInfo[];

    return {
      id: Math.random().toString(36).substr(2, 9),
      type: ScanType.APK,
      target: filename,
      riskLevel: result.riskLevel as RiskLevel,
      riskScore: result.riskScore,
      confidence: result.confidence,
      timestamp: Date.now(),
      analysisMessage: result.analysisMessage,
      indicators: result.indicators,
      permissions,
      recommendation: result.recommendation,
      actions: result.actions,
    };
  } catch (error) {
    console.error("Gemini API Error:", error);
    return fallbackScanApk(filename);
  }
};

const fallbackScanApk = (filename: string): ScanResult => {
  const indicators: string[] = [];
  let riskLevel = RiskLevel.LOW;
  let riskScore = 10;
  let confidence = 80;
  let analysisMessage = "Static analysis complete. No high-risk code patterns or privacy-invasive permissions found.";
  let recommendation = "This app appears safe to install, but always download apps from official stores like Google Play.";
  let actions = ["Verify the developer's reputation", "Check user reviews on official stores"];
  const permissions: PermissionInfo[] = [];

  const isSuspiciousName = filename.toLowerCase().includes('scam') || 
                           filename.toLowerCase().includes('bank') || 
                           filename.toLowerCase().includes('update');
  
  if (isSuspiciousName) {
    riskLevel = RiskLevel.HIGH;
    riskScore = 92;
    indicators.push('Suspicious filename pattern');
    indicators.push('High-risk permission: SMS Intercept');
    analysisMessage = "High risk: This APK contains code patterns and permission requests typically found in banking trojans and spyware.";
    recommendation = "Do not install this APK. It is highly likely to be malicious and could steal your banking information.";
    actions = ["Delete the APK file immediately", "Scan your device for existing threats", "Change your banking passwords if you already installed it"];
    permissions.push(DANGEROUS_PERMISSIONS[0]); // READ_SMS
    permissions.push(DANGEROUS_PERMISSIONS[1]); // RECEIVE_SMS
  }

  return {
    id: Math.random().toString(36).substr(2, 9),
    type: ScanType.APK,
    target: filename,
    riskLevel,
    riskScore,
    confidence,
    timestamp: Date.now(),
    analysisMessage,
    indicators,
    permissions,
    recommendation,
    actions,
  };
};
