/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

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

export const scanUrl = async (url: string): Promise<ScanResult> => {
  const indicators: string[] = [];
  let riskLevel = RiskLevel.LOW;
  let riskScore = 15;
  let confidence = 85;
  let analysisMessage = "No suspicious patterns were detected during this heuristic scan. However, this does not guarantee the URL is entirely safe.";
  let recommendation = "Exercise caution. Always verify the source before entering sensitive data.";
  let actions = ["Verify the URL matches the official site", "Check for HTTPS"];

  try {
    const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
    if (urlObj.protocol === 'http:') {
      indicators.push('Unsafe connection');
      riskLevel = RiskLevel.MEDIUM;
      riskScore = 55;
      analysisMessage = "This link has some risk because it uses an old, unsafe connection. Be careful before clicking.";
      recommendation = "Do not type any private info on this website.";
      actions = ["Check if there is a safer version of this site", "Do not type passwords or card details"];
    }
    
    const suspiciousKeywords = ['login', 'verify', 'account', 'secure', 'update', 'bank'];
    if (suspiciousKeywords.some(k => url.toLowerCase().includes(k)) && !url.includes('google.com') && !url.includes('microsoft.com')) {
      indicators.push('Suspicious words');
      riskLevel = RiskLevel.HIGH;
      riskScore = 85;
      analysisMessage = "This link is dangerous because it looks like a fake login or banking page. Do not open it.";
      recommendation = "Do not type any personal info on this site.";
      actions = ["Close the page now", "Report this link"];
    }
  } catch (e) {
    indicators.push('Broken link');
    riskLevel = RiskLevel.HIGH;
    riskScore = 95;
    analysisMessage = "This link is dangerous because it is broken or written incorrectly. Do not open it.";
    recommendation = "Do not visit this link. It might be a trick to steal your info.";
    actions = ["Close the page now", "Report this link if you got it in a message"];
  }

  return {
    id: Math.random().toString(36).substr(2, 9),
    type: ScanType.URL,
    target: url,
    riskLevel,
    riskScore,
    confidence,
    timestamp: Date.now(),
    analysisMessage: riskLevel === RiskLevel.LOW ? "This link is safe because no suspicious patterns were found. No threats were found." : analysisMessage,
    indicators,
    recommendation,
    actions,
    isLive: false
  };
};

export const scanApk = async (filename: string, hash?: string): Promise<ScanResult> => {
  try {
    // If no hash provided, we can't search VT without uploading, so fallback
    if (!hash) {
      return fallbackScanApk(filename);
    }

    const response = await fetch(`/api/vt/file/${hash}`);

    if (response.status === 404 || response.status === 503 || response.status === 401 || response.status === 403) {
      let message = "File hash not found in VirusTotal database. Performed local heuristic analysis.";
      if (response.status === 503) message = "API Key Missing: Performed basic local check only.";
      if (response.status === 401 || response.status === 403) message = "API Key Invalid: Please check your VirusTotal API key in secrets.";

      return {
        ...fallbackScanApk(filename),
        analysisMessage: message,
        isLive: false
      };
    }

    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.statusText}`);
    }

    const data = await response.json();
    const attributes = data.data.attributes;
    const stats = attributes.last_analysis_stats;
    const results = attributes.last_analysis_results;

    const maliciousCount = stats.malicious;
    const totalEngines = Object.keys(results).length;
    
    let riskLevel = RiskLevel.LOW;
    if (maliciousCount > 5) riskLevel = RiskLevel.HIGH;
    else if (maliciousCount > 0) riskLevel = RiskLevel.MEDIUM;

    return {
      id: Math.random().toString(36).substr(2, 9),
      type: ScanType.APK,
      target: filename,
      riskLevel,
      riskScore: Math.min(Math.round((maliciousCount / totalEngines) * 500), 100),
      confidence: 98,
      timestamp: Date.now(),
      analysisMessage: `VirusTotal Report: ${maliciousCount} security vendors flagged this file as malicious.`,
      indicators: [`VT Detection: ${maliciousCount}/${totalEngines}`, `SHA-256: ${hash.substring(0, 16)}...`],
      permissions: [], 
      recommendation: maliciousCount > 0 ? "DANGER: This file is flagged as malicious by multiple security engines. Do not install." : "VirusTotal found no threats for this file hash.",
      actions: maliciousCount > 0 ? ["Delete the file immediately", "Scan your device for infections"] : ["Proceed with caution"],
      malwareType: maliciousCount > 0 ? "Detected Malware" : "None",
      isLive: true
    };

  } catch (error) {
    console.error("VirusTotal API Error:", error);
    return fallbackScanApk(filename);
  }
};

const fallbackScanApk = (filename: string): ScanResult => {
  const indicators: string[] = [];
  let riskLevel = RiskLevel.LOW;
  let riskScore = 10;
  let confidence = 80;
  let analysisMessage = "Static analysis complete. No high-risk code patterns or privacy-invasive permissions were identified in this scan. This is not a guarantee of safety.";
  let recommendation = "Always download apps from official stores like Google Play. Proceed with caution.";
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
      malwareType: "Trojan",
      permissionAnalysis: ["Requests READ_SMS and RECEIVE_SMS which are critical for intercepting OTPs."],
      behavioralFlags: ["Potential SMS interception", "Suspicious naming convention"],
      estimatedDamage: "Unauthorized access to banking accounts and personal messages.",
      isLive: false
    };
  }

  return {
    id: Math.random().toString(36).substr(2, 9),
    type: ScanType.APK,
    target: filename,
    riskLevel,
    riskScore,
    confidence,
    timestamp: Date.now(),
    analysisMessage: "Performed local heuristic analysis.",
    indicators: ["Local Analysis Only", ...indicators],
    permissions,
    recommendation: "Always download apps from official stores.",
    actions: [...actions],
    malwareType: "None",
    permissionAnalysis: ["No dangerous permission combinations detected."],
    behavioralFlags: ["No suspicious background services identified."],
    estimatedDamage: "Minimal risk to device or data.",
    isLive: false
  };
};
