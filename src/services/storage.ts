/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ScanResult, AppStats } from '../types';

const STORAGE_KEY = 'apkurl_blocker_history';

export const saveScanResult = (result: ScanResult) => {
  const history = getScanHistory();
  // Remove any existing entry for the same target to ensure it only appears once
  const filteredHistory = history.filter(h => h.target !== result.target);
  const newHistory = [result, ...filteredHistory];
  localStorage.setItem(STORAGE_KEY, JSON.stringify(newHistory));
};

export const getScanHistory = (): ScanResult[] => {
  const data = localStorage.getItem(STORAGE_KEY);
  return data ? JSON.parse(data) : [];
};

export const deleteScanResult = (id: string) => {
  const history = getScanHistory();
  const newHistory = history.filter(h => h.id !== id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(newHistory));
};

export const clearHistory = () => {
  localStorage.removeItem(STORAGE_KEY);
};

export const getAppStats = (): AppStats => {
  const history = getScanHistory();
  const highRiskCount = history.filter(h => h.riskLevel === 'HIGH').length;
  const lastScanTime = history.length > 0 ? history[0].timestamp : null;

  return {
    totalScans: history.length,
    highRiskCount,
    lastScanTime,
  };
};
