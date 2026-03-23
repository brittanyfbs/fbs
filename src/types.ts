/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
}

export enum ScanType {
  URL = 'URL',
  APK = 'APK',
}

export interface ScanResult {
  id: string;
  type: ScanType;
  target: string;
  riskLevel: RiskLevel;
  riskScore: number;
  confidence: number;
  timestamp: number;
  analysisMessage: string;
  indicators: string[];
  permissions?: PermissionInfo[];
  recommendation?: string;
  actions?: string[];
  // Advanced APK fields
  malwareType?: string;
  permissionAnalysis?: string[];
  behavioralFlags?: string[];
  estimatedDamage?: string;
  isLive?: boolean;
}

export interface PermissionInfo {
  name: string;
  description: string;
  severity: RiskLevel;
}

export interface AppStats {
  totalScans: number;
  highRiskCount: number;
  lastScanTime: number | null;
}
