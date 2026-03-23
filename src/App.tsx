/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef } from 'react';
import { BrowserRouter as Router, Routes, Route, useNavigate, useLocation, Link, useParams } from 'react-router-dom';
import { Shield, Home as HomeIcon, Clock, Settings as SettingsIcon, ChevronRight, Globe, Smartphone, AlertTriangle, CheckCircle2, X, ArrowLeft, Upload, Trash2, Info, Zap, ShieldAlert, Activity, FileText, Layout } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { RiskLevel, ScanType, ScanResult } from './types';
import { COLORS, RISK_LABELS } from './constants';
import { getScanHistory, getAppStats, saveScanResult, clearHistory, deleteScanResult } from './services/storage';
import { scanUrl, scanApk } from './services/scanner';
import { generateAnalysisSummary } from './services/geminiService';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

// --- Utilities ---
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Components ---

const TopBar = ({ title, showBack = false, onBack, rightElement }: { title: string, showBack?: boolean, onBack?: () => void, rightElement?: React.ReactNode }) => (
  <div className="bg-white px-4 py-4 flex items-center justify-between sticky top-0 z-50">
    <div className="flex items-center">
      {showBack ? (
        <button onClick={onBack} className="mr-4 text-gray-800">
          <ArrowLeft size={24} />
        </button>
      ) : (
        <div className="mr-3 text-[#1E7FFF]">
          <Shield size={28} fill="#1E7FFF" />
        </div>
      )}
      <h1 className={cn("text-xl font-bold text-gray-900", !showBack && "text-2xl")}>{title}</h1>
    </div>
    {rightElement}
  </div>
);

const BottomNav = () => {
  const location = useLocation();
  const isActive = (path: string) => location.pathname === path;

  const tabs = [
    { path: '/', icon: HomeIcon, label: 'Home' },
    { path: '/history', icon: Clock, label: 'History' },
    { path: '/settings', icon: SettingsIcon, label: 'Settings' },
  ];

  return (
    <div className="fixed bottom-0 left-0 right-0 bg-white border-t border-gray-100 flex justify-around py-3 px-6 z-50">
      {tabs.map((tab) => {
        const ActiveIcon = tab.icon;
        const active = isActive(tab.path);
        return (
          <Link 
            key={tab.path}
            to={tab.path} 
            className={cn(
              "flex flex-col items-center justify-center w-16 h-12 rounded-2xl transition-all duration-200",
              active ? "text-[#1E7FFF] bg-blue-50" : "text-gray-400"
            )}
          >
            <ActiveIcon size={24} strokeWidth={active ? 2.5 : 2} />
            <span className={cn("text-[10px] mt-1 font-bold uppercase tracking-wider", active ? "opacity-100" : "opacity-0")}>
              {tab.label}
            </span>
          </Link>
        );
      })}
    </div>
  );
};

const RiskBadge = ({ level, large = false }: { level: RiskLevel, large?: boolean }) => {
  const color = level === RiskLevel.HIGH ? COLORS.HIGH : level === RiskLevel.MEDIUM ? COLORS.MEDIUM : COLORS.LOW;
  return (
    <div 
      className={cn(
        "rounded-full text-white font-bold flex items-center justify-center",
        large ? "px-6 py-2 text-sm" : "px-3 py-1 text-[10px]"
      )}
      style={{ backgroundColor: color }}
    >
      {RISK_LABELS[level]}
    </div>
  );
};

// --- Pages ---

const HomePage = () => {
  const navigate = useNavigate();
  const stats = getAppStats();
  const recentScans = getScanHistory().slice(0, 3);

  return (
    <div className="pb-24 bg-white min-h-screen">
      <TopBar title="APKURL" />
      <div className="px-5 space-y-6">
        <div className="pt-2">
          <h2 className="text-3xl font-extrabold text-gray-900">Security Center</h2>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <button 
            onClick={() => navigate('/scan-url')}
            className="bg-white p-5 rounded-3xl flex flex-col items-start justify-between shadow-sm border border-gray-100 active:scale-95 transition-transform text-left h-40"
          >
            <div className="bg-blue-50 p-3 rounded-2xl text-[#1E7FFF]">
              <Globe size={28} />
            </div>
            <div>
              <p className="font-bold text-gray-900 text-lg">Scan URL</p>
              <p className="text-xs text-gray-500">Analyze phishing links</p>
            </div>
          </button>
          <button 
            onClick={() => navigate('/scan-apk')}
            className="bg-white p-5 rounded-3xl flex flex-col items-start justify-between shadow-sm border border-gray-100 active:scale-95 transition-transform text-left h-40"
          >
            <div className="bg-blue-50 p-3 rounded-2xl text-[#1E7FFF]">
              <Smartphone size={28} />
            </div>
            <div>
              <p className="font-bold text-gray-900 text-lg">Scan APK</p>
              <p className="text-xs text-gray-500">Analyze app safety</p>
            </div>
          </button>
        </div>

        <div className="bg-[#1F1F1F] rounded-3xl p-6 shadow-xl">
          <p className="text-[10px] text-gray-500 font-bold uppercase tracking-[0.2em] mb-4">Dashboard Overview</p>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-3xl font-black text-[#1E7FFF]">{stats.totalScans}</p>
              <p className="text-[10px] text-gray-400 font-bold uppercase">Total Scans</p>
            </div>
            <div>
              <p className="text-3xl font-black text-[#FF5252]">{stats.highRiskCount}</p>
              <p className="text-[10px] text-gray-400 font-bold uppercase">High Risks</p>
            </div>
          </div>
          <div className="mt-6 pt-4 border-t border-gray-800">
            <p className="text-[10px] text-gray-500 font-medium italic">
              Last Scan Activity: {stats.lastScanTime ? new Date(stats.lastScanTime).toLocaleString() : 'No activity yet'}
            </p>
          </div>
        </div>

        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="font-bold text-gray-900 text-lg">Recent Activity</h3>
            <Link to="/history" className="text-[#1E7FFF] text-xs font-bold flex items-center">
              ALL HISTORY <ChevronRight size={14} className="ml-1" />
            </Link>
          </div>

          <div className="space-y-3">
            {recentScans.length === 0 ? (
              <div className="text-center py-8 text-gray-400 bg-gray-50 rounded-2xl border border-dashed border-gray-200">
                <p className="text-sm">No recent scans</p>
              </div>
            ) : (
              recentScans.map(scan => (
                <div 
                  key={scan.id} 
                  className="bg-white p-4 rounded-2xl border border-gray-100 flex items-center shadow-sm active:bg-gray-50 transition-colors"
                  onClick={() => navigate(`/result/${scan.id}`)}
                >
                  <div className="p-3 rounded-xl bg-gray-50 text-gray-400 mr-4">
                    {scan.type === ScanType.URL ? <Globe size={20} /> : <Smartphone size={20} />}
                  </div>
                  <div className="flex-1 overflow-hidden">
                    <p className="font-bold text-gray-900 truncate text-sm">{scan.target}</p>
                    <p className="text-[10px] text-gray-400 mt-0.5">
                      {new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </p>
                  </div>
                  <RiskBadge level={scan.riskLevel} />
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const ScanUrlPage = () => {
  const [url, setUrl] = useState('');
  const navigate = useNavigate();

  const handleScan = () => {
    if (url.trim()) {
      navigate('/scanning', { state: { type: ScanType.URL, target: url } });
    }
  };

  return (
    <div className="min-h-screen bg-white pb-10">
      <TopBar title="URL Scanner" showBack onBack={() => navigate(-1)} />
      <div className="px-6 py-4">
        <p className="text-gray-500 mb-8 leading-relaxed">
          Analyze links for phishing patterns and malicious redirects instantly.
        </p>
        
        <div className="space-y-6">
          <div className="relative group">
            <div className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 group-focus-within:text-[#1E7FFF] transition-colors">
              <Globe size={20} />
            </div>
            <input 
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://suspicious-link.com"
              className="w-full bg-gray-50 border border-gray-200 rounded-2xl px-12 py-4 focus:outline-none focus:ring-2 focus:ring-[#1E7FFF] focus:bg-white transition-all text-gray-900 font-medium"
            />
            {url && (
              <button 
                onClick={() => setUrl('')}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                <X size={20} />
              </button>
            )}
          </div>

          <button 
            onClick={handleScan}
            disabled={!url.trim()}
            className="w-full bg-gradient-to-r from-[#1E7FFF] to-[#0062FF] text-white py-4 rounded-2xl font-bold shadow-lg active:scale-[0.98] transition-all disabled:from-gray-300 disabled:to-gray-400 disabled:shadow-none"
          >
            Start Security Analysis
          </button>
        </div>

        <div className="mt-12">
          <h3 className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-6">AI Capabilities</h3>
          <ul className="space-y-4">
            {['TYPOSQUATTING DETECTION', 'DOMAIN TRUST VERIFICATION', 'SUSPICIOUS METADATA ANALYSIS'].map((item) => (
              <li key={item} className="flex items-center text-xs font-bold text-gray-700">
                <div className="w-1.5 h-1.5 rounded-full bg-[#1E7FFF] mr-3" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

const ScanningPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { type, target } = location.state || {};
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('Initializing...');
  const scanPerformed = useRef(false);

  useEffect(() => {
    if (!type || !target) {
      navigate('/');
      return;
    }

    if (scanPerformed.current) return;
    scanPerformed.current = true;

    const startTime = Date.now();
    const duration = 4000; // 4 seconds for a smooth feel

    const updateProgress = () => {
      const now = Date.now();
      const elapsed = now - startTime;
      const rawProgress = Math.min((elapsed / duration) * 100, 99);
      
      setProgress(Math.floor(rawProgress));

      // Update status messages based on progress
      if (rawProgress < 20) setStatus('Initializing AI engine...');
      else if (rawProgress < 40) setStatus(type === ScanType.URL ? 'Analyzing URL structure...' : 'Decompiling APK...');
      else if (rawProgress < 60) setStatus('Checking against threat database...');
      else if (rawProgress < 80) setStatus('Running heuristic analysis...');
      else setStatus('Finalizing security report...');

      if (elapsed < duration) {
        requestAnimationFrame(updateProgress);
      }
    };

    const performScan = async () => {
      requestAnimationFrame(updateProgress);
      
      const { hash } = location.state || {};
      const scanPromise = type === ScanType.URL ? scanUrl(target) : scanApk(target, hash);
      
      // Wait for both the scan and the minimum duration
      const [result] = await Promise.all([
        scanPromise,
        new Promise(resolve => setTimeout(resolve, duration))
      ]);
      
      // Generate AI Summary
      setStatus('Generating AI Summary...');
      const aiSummary = await generateAnalysisSummary(result);
      result.analysisMessage = aiSummary.analysisMessage || result.analysisMessage;
      result.indicators = aiSummary.indicators || result.indicators;
      result.recommendation = aiSummary.recommendation || result.recommendation;
      
      setProgress(100);
      setStatus('Scan Complete');
      saveScanResult(result);
      
      setTimeout(() => {
        navigate(`/result/${result.id}`, { replace: true });
      }, 600);
    };

    performScan();
  }, [type, target, navigate]);

  return (
    <div className="min-h-screen bg-white flex flex-col">
      <TopBar title={type === ScanType.URL ? "Scanning URL" : "Scanning APK"} showBack onBack={() => navigate(-1)} />
      <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
        <div className="relative w-64 h-64 mb-12">
          {/* Background Circle */}
          <svg className="w-full h-full" viewBox="0 0 100 100">
            <circle 
              cx="50" cy="50" r="45" 
              fill="none" stroke="#F3F4F6" strokeWidth="6" 
            />
            {/* Progress Circle */}
            <motion.circle 
              cx="50" cy="50" r="45" 
              fill="none" stroke="#1E7FFF" strokeWidth="6" 
              strokeDasharray="283"
              initial={{ strokeDashoffset: 283 }}
              animate={{ strokeDashoffset: 283 - (283 * progress) / 100 }}
              transition={{ duration: 0.1, ease: "linear" }}
              strokeLinecap="round"
              transform="rotate(-90 50 50)"
            />
          </svg>
          
          {/* Inner Content */}
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <motion.span 
              key={progress}
              initial={{ opacity: 0.5, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-6xl font-black text-gray-900 tracking-tighter"
            >
              {progress}<span className="text-2xl opacity-30 ml-1">%</span>
            </motion.span>
            <div className="mt-2 px-4 py-1 bg-blue-50 rounded-full">
              <span className="text-[10px] font-black text-[#1E7FFF] uppercase tracking-widest">
                {progress === 100 ? 'SECURED' : 'ANALYZING'}
              </span>
            </div>
          </div>

          {/* Decorative Pulse */}
          <motion.div 
            className="absolute inset-0 rounded-full border-2 border-[#1E7FFF]/20"
            animate={{ scale: [1, 1.1, 1], opacity: [0.5, 0, 0.5] }}
            transition={{ duration: 2, repeat: Infinity }}
          />
        </div>

        <div className="space-y-3">
          <h2 className="text-2xl font-black text-gray-900">
            {type === ScanType.URL ? "URL Security Scan" : "APK Threat Analysis"}
          </h2>
          <div className="flex items-center justify-center space-x-2">
            <div className="w-1.5 h-1.5 rounded-full bg-[#1E7FFF] animate-bounce" style={{ animationDelay: '0ms' }} />
            <div className="w-1.5 h-1.5 rounded-full bg-[#1E7FFF] animate-bounce" style={{ animationDelay: '150ms' }} />
            <div className="w-1.5 h-1.5 rounded-full bg-[#1E7FFF] animate-bounce" style={{ animationDelay: '300ms' }} />
            <p className="text-sm font-bold text-gray-500 min-w-[200px]">
              {status}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

const ResultPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const scan = useMemo(() => getScanHistory().find(h => h.id === id), [id]);

  if (!scan) return <div>Not found</div>;

  const isHigh = scan.riskLevel === RiskLevel.HIGH;
  const isMedium = scan.riskLevel === RiskLevel.MEDIUM;
  const isLow = scan.riskLevel === RiskLevel.LOW;

  const badgeColor = isHigh ? COLORS.HIGH : isMedium ? COLORS.MEDIUM : COLORS.LOW;

  return (
    <div className="min-h-screen bg-[#F8F9FA] pb-10 flex flex-col">
      <TopBar 
        title="Security Report" 
        rightElement={
          <button 
            onClick={() => navigate('/')}
            className="text-[#1E7FFF] text-xs font-bold"
          >
            Done
          </button>
        } 
      />
      
      <div className="px-5 py-4 space-y-6 flex-1">
        {/* Summary Card */}
        <div 
          className="rounded-[32px] p-8 flex flex-col items-center justify-center text-white shadow-2xl relative overflow-hidden"
          style={{ backgroundColor: badgeColor }}
        >
          <div className="absolute top-0 right-0 p-4 opacity-10">
            <Shield size={120} />
          </div>
          <div className="bg-white/20 p-4 rounded-3xl mb-4 relative z-10">
            <AlertTriangle size={40} />
          </div>
          <h2 className="text-3xl font-black mb-1 relative z-10">{RISK_LABELS[scan.riskLevel]}</h2>
          <p className="text-[10px] font-bold opacity-80 uppercase tracking-widest mb-6 relative z-10">
            {scan.malwareType && scan.malwareType !== "None" ? `${scan.malwareType} Detected` : "System Analysis Complete"}
          </p>
          
          <div className="grid grid-cols-2 gap-4 w-full relative z-10">
            <div className="bg-black/20 backdrop-blur-md rounded-2xl p-3 flex flex-col items-center border border-white/10">
              <span className="text-[8px] font-black uppercase tracking-widest opacity-70 mb-1">Risk Score</span>
              <span className="text-xl font-black">{scan.riskScore}%</span>
            </div>
            <div className="bg-black/20 backdrop-blur-md rounded-2xl p-3 flex flex-col items-center border border-white/10">
              <span className="text-[8px] font-black uppercase tracking-widest opacity-70 mb-1">Confidence</span>
              <span className="text-xl font-black">{scan.confidence}%</span>
            </div>
          </div>
        </div>

        {/* API Warning */}
        {!scan.isLive && scan.type === ScanType.APK && (
          <div className="bg-orange-50 border border-orange-100 rounded-2xl p-4 flex items-start">
            <Info size={18} className="text-orange-500 mr-3 mt-0.5 flex-shrink-0" />
            <div>
              <p className="text-xs font-bold text-orange-900 mb-1">Local Analysis Only</p>
              <p className="text-[10px] text-orange-700 leading-relaxed">
                VirusTotal API key is not configured. This scan only checked for basic suspicious patterns and may not be accurate. Add your API key in the Secrets panel to enable full security scanning.
              </p>
            </div>
          </div>
        )}

        {/* Analysis Content */}
        <div className="space-y-6">
          <motion.div 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            <div>
              <h3 className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-3">Analysis Summary</h3>
              <div className="bg-white p-6 rounded-[32px] border border-gray-100 shadow-sm">
                <p className="text-sm text-gray-700 leading-relaxed font-medium">
                  {scan.analysisMessage}
                </p>
              </div>
            </div>

            {scan.indicators && scan.indicators.length > 0 && (
              <div>
                <h3 className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-3">Key Reasons</h3>
                <div className="bg-white p-6 rounded-[32px] border border-gray-100 shadow-sm space-y-3">
                  {scan.indicators.map((reason, idx) => (
                    <div key={idx} className="flex items-start">
                      <div className="w-1.5 h-1.5 rounded-full bg-[#1E7FFF] mt-1.5 mr-3 flex-shrink-0" />
                      <p className="text-xs text-gray-600 font-medium leading-relaxed">{reason}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {scan.recommendation && (
              <div>
                <h3 className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-3">Recommendation</h3>
                <div className="bg-blue-50 p-6 rounded-[32px] border border-blue-100">
                  <p className="text-xs text-blue-900 font-bold leading-relaxed">
                    {scan.recommendation}
                  </p>
                </div>
              </div>
            )}
          </motion.div>
        </div>
      </div>

      <div className="px-5 pt-4">
        <button 
          onClick={() => navigate('/')}
          className="w-full bg-[#1A1A1A] text-white py-5 rounded-2xl font-black text-sm shadow-xl active:scale-[0.98] transition-all"
        >
          Close Report
        </button>
      </div>
    </div>
  );
};

const ScanApkPage = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isHashing, setIsHashing] = useState(false);
  
  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setIsHashing(true);
      try {
        // Calculate hash before navigating
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        navigate('/scanning', { state: { type: ScanType.APK, target: file.name, hash } });
      } catch (err) {
        console.error("Hashing error:", err);
        navigate('/scanning', { state: { type: ScanType.APK, target: file.name } });
      } finally {
        setIsHashing(false);
      }
    }
  };

  const triggerFileInput = () => {
    fileInputRef.current?.click();
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const file = e.dataTransfer.files?.[0];
    if (file && file.name.endsWith('.apk')) {
      setIsHashing(true);
      try {
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        navigate('/scanning', { state: { type: ScanType.APK, target: file.name, hash } });
      } catch (err) {
        console.error("Hashing error:", err);
        navigate('/scanning', { state: { type: ScanType.APK, target: file.name } });
      } finally {
        setIsHashing(false);
      }
    }
  };

  return (
    <div className="min-h-screen bg-white pb-10">
      <TopBar title="APK Scanner" showBack onBack={() => navigate(-1)} />
      <div className="px-6 py-4">
        <p className="text-gray-500 mb-10 leading-relaxed">
          Select an APK file to analyze its code structure and privacy permissions.
        </p>
        
        <input 
          type="file" 
          ref={fileInputRef} 
          onChange={handleFileChange} 
          accept=".apk" 
          className="hidden" 
        />

        <div 
          onClick={isHashing ? undefined : triggerFileInput}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          className={cn(
            "w-full border-2 border-dashed border-gray-200 rounded-[32px] p-12 flex flex-col items-center justify-center text-gray-400 cursor-pointer active:bg-gray-50 transition-all bg-gray-50/50 hover:border-[#1E7FFF] hover:bg-blue-50/30 group",
            isHashing && "opacity-50 cursor-wait"
          )}
        >
          <div className="bg-white p-5 rounded-3xl shadow-sm mb-4 text-[#1E7FFF] group-hover:scale-110 transition-transform">
            {isHashing ? <Activity className="animate-spin" size={32} /> : <Upload size={32} />}
          </div>
          <p className="font-black text-gray-900 mb-1">{isHashing ? 'Analyzing File...' : 'Choose APK File'}</p>
          <p className="text-[10px] font-bold uppercase tracking-widest">{isHashing ? 'Please wait' : 'Or drag and drop'}</p>
        </div>

        <div className="mt-12">
          <h3 className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-4">Analysis Depth</h3>
          <p className="text-sm text-gray-600 leading-relaxed font-medium">
            We perform a deep static analysis to identify high-risk permissions such as SMS intercepts, background location tracking, and camera access.
          </p>
        </div>
      </div>
    </div>
  );
};

const HistoryPage = () => {
  const navigate = useNavigate();
  const [history, setHistory] = useState<ScanResult[]>([]);

  useEffect(() => {
    setHistory(getScanHistory());
  }, []);

  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const handleDeleteAll = () => {
    clearHistory();
    setHistory([]);
    setShowDeleteConfirm(false);
  };

  const handleDeleteItem = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    deleteScanResult(id);
    setHistory(prev => prev.filter(h => h.id !== id));
  };

  return (
    <div className="pb-24 bg-white min-h-screen">
      <TopBar 
        title="Scan History" 
        rightElement={
          <button onClick={() => setShowDeleteConfirm(true)} className="text-red-500 p-2">
            <Trash2 size={20} />
          </button>
        }
      />
      
      <div className="px-5 space-y-6">
        <div className="space-y-3">
          {history.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-gray-300">
              <Clock size={64} className="mb-4 opacity-20" />
              <p className="text-sm font-bold">No history found</p>
            </div>
          ) : (
            history.map(scan => (
              <div 
                key={scan.id} 
                className="bg-white p-4 rounded-2xl border border-gray-100 flex items-center shadow-sm active:bg-gray-50 transition-colors group"
                onClick={() => navigate(`/result/${scan.id}`)}
              >
                <div className="p-3 rounded-xl bg-gray-50 text-gray-400 mr-4">
                  {scan.type === ScanType.URL ? <Globe size={20} /> : <Smartphone size={20} />}
                </div>
                <div className="flex-1 overflow-hidden pr-2">
                  <p className="font-bold text-gray-900 truncate text-sm">{scan.target}</p>
                  <p className="text-[10px] text-gray-400 mt-0.5">
                    {new Date(scan.timestamp).toLocaleString()}
                  </p>
                </div>
                <div className="flex items-center">
                  <RiskBadge level={scan.riskLevel} />
                  <button 
                    onClick={(e) => handleDeleteItem(e, scan.id)}
                    className="ml-3 text-gray-300 hover:text-red-500 transition-colors opacity-0 group-hover:opacity-100"
                  >
                    <X size={16} />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      <AnimatePresence>
        {showDeleteConfirm && (
          <div className="fixed inset-0 z-[200] flex items-center justify-center p-6">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowDeleteConfirm(false)}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white rounded-[32px] p-8 w-full max-w-xs relative z-10 shadow-2xl text-center"
            >
              <div className="bg-red-50 text-red-500 w-16 h-16 rounded-3xl flex items-center justify-center mx-auto mb-6">
                <Trash2 size={32} />
              </div>
              <h3 className="text-xl font-black text-gray-900 mb-2">Clear History?</h3>
              <p className="text-sm text-gray-500 mb-8 leading-relaxed">
                This will permanently delete all your scan records. This action cannot be undone.
              </p>
              <div className="space-y-3">
                <button 
                  onClick={handleDeleteAll}
                  className="w-full bg-red-500 text-white py-4 rounded-2xl font-bold shadow-lg shadow-red-200 active:scale-95 transition-all"
                >
                  Yes, Clear All
                </button>
                <button 
                  onClick={() => setShowDeleteConfirm(false)}
                  className="w-full bg-gray-100 text-gray-600 py-4 rounded-2xl font-bold active:scale-95 transition-all"
                >
                  Cancel
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};

const SettingsPage = () => {
  const [showPrivacy, setShowPrivacy] = useState(false);
  const [realTime, setRealTime] = useState(true);
  const [autoScan, setAutoScan] = useState(false);
  const [configStatus, setConfigStatus] = useState<{ virustotal: boolean, gemini: boolean } | null>(null);

  useEffect(() => {
    fetch('/api/config/status')
      .then(res => res.json())
      .then(setConfigStatus)
      .catch(() => setConfigStatus({ virustotal: false, gemini: false }));
  }, []);

  return (
    <div className="pb-24 bg-white min-h-screen">
      <TopBar title="Settings" />
      <div className="px-5 py-4 space-y-8">
        {/* App Settings Section */}
        <div>
          <h3 className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-4 px-1">Security Engines</h3>
          <div className="bg-white rounded-3xl overflow-hidden border border-gray-100 shadow-sm">
            <div className="p-5 flex items-center justify-between border-b border-gray-50">
              <div className="flex items-center">
                <div className="bg-blue-50 p-2 rounded-xl text-[#1E7FFF] mr-3">
                  <Zap size={18} />
                </div>
                <div>
                  <p className="font-bold text-gray-900 text-sm">VirusTotal API</p>
                  <p className="text-[10px] text-gray-400 font-medium">For APK scanning</p>
                </div>
              </div>
              <div className={cn(
                "px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider",
                configStatus?.virustotal ? "bg-green-50 text-green-600" : "bg-red-50 text-red-600"
              )}>
                {configStatus?.virustotal ? "Connected" : "Disconnected"}
              </div>
            </div>
            <div className="p-5 flex items-center justify-between">
              <div className="flex items-center">
                <div className="bg-blue-50 p-2 rounded-xl text-[#1E7FFF] mr-3">
                  <Activity size={18} />
                </div>
                <div>
                  <p className="font-bold text-gray-900 text-sm">Gemini AI</p>
                  <p className="text-[10px] text-gray-400 font-medium">For analysis summaries</p>
                </div>
              </div>
              <div className={cn(
                "px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider",
                configStatus?.gemini ? "bg-green-50 text-green-600" : "bg-red-50 text-red-600"
              )}>
                {configStatus?.gemini ? "Connected" : "Disconnected"}
              </div>
            </div>
          </div>
          {!configStatus?.virustotal && (
            <p className="mt-3 px-2 text-[10px] text-gray-400 leading-relaxed italic">
              * Add VIRUSTOTAL_API_KEY to secrets to enable full scanning.
            </p>
          )}
        </div>

        {/* App Settings Section */}
        <div>
          <h3 className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-4 px-1">App Settings</h3>
          <div className="bg-white rounded-3xl overflow-hidden border border-gray-100 shadow-sm">
            <div className="p-5 flex items-center justify-between border-b border-gray-50">
              <div className="flex items-center">
                <div className="bg-blue-50 p-2 rounded-xl text-[#1E7FFF] mr-3">
                  <Shield size={18} />
                </div>
                <p className="font-bold text-gray-900 text-sm">Real-time Protection</p>
              </div>
              <button 
                onClick={() => setRealTime(!realTime)}
                className={cn(
                  "w-12 h-6 rounded-full transition-all duration-300 relative",
                  realTime ? "bg-[#1E7FFF]" : "bg-gray-200"
                )}
              >
                <div className={cn(
                  "absolute top-1 w-4 h-4 bg-white rounded-full transition-all duration-300",
                  realTime ? "left-7" : "left-1"
                )} />
              </button>
            </div>
            <div className="p-5 flex items-center justify-between border-b border-gray-50">
              <div className="flex items-center">
                <div className="bg-blue-50 p-2 rounded-xl text-[#1E7FFF] mr-3">
                  <Clock size={18} />
                </div>
                <p className="font-bold text-gray-900 text-sm">Auto-scan Downloads</p>
              </div>
              <button 
                onClick={() => setAutoScan(!autoScan)}
                className={cn(
                  "w-12 h-6 rounded-full transition-all duration-300 relative",
                  autoScan ? "bg-[#1E7FFF]" : "bg-gray-200"
                )}
              >
                <div className={cn(
                  "absolute top-1 w-4 h-4 bg-white rounded-full transition-all duration-300",
                  autoScan ? "left-7" : "left-1"
                )} />
              </button>
            </div>
          </div>
        </div>

        {/* Support Section */}
        <div>
          <h3 className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-4 px-1">Support & Info</h3>
          <div className="bg-gray-50 rounded-3xl overflow-hidden border border-gray-100">
            <div className="p-5 flex items-center justify-between border-b border-gray-200/50">
              <div className="flex items-center">
                <Info size={20} className="text-[#1E7FFF] mr-3" />
                <p className="font-bold text-gray-900 text-sm">App Version</p>
              </div>
              <p className="text-gray-400 font-black text-xs">V4.3.0</p>
            </div>
            <button 
              onClick={() => setShowPrivacy(true)}
              className="w-full p-5 flex items-center justify-between active:bg-gray-100 transition-colors"
            >
              <div className="flex items-center">
                <Shield size={20} className="text-[#1E7FFF] mr-3" />
                <p className="font-bold text-gray-900 text-sm">Privacy Policy</p>
              </div>
              <ChevronRight size={20} className="text-gray-300" />
            </button>
          </div>
        </div>

        <div className="bg-blue-50 p-6 rounded-3xl border border-blue-100">
          <p className="text-xs text-blue-800 font-bold leading-relaxed">
            APKURL uses advanced AI heuristics to protect your digital life. Always exercise caution when interacting with unknown links or apps.
          </p>
        </div>
      </div>

      <AnimatePresence>
        {showPrivacy && (
          <motion.div 
            initial={{ opacity: 0, y: 100 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 100 }}
            className="fixed inset-0 z-[100] bg-white overflow-y-auto"
          >
            <TopBar title="Privacy Policy" showBack onBack={() => setShowPrivacy(false)} />
            <div className="px-6 py-6 space-y-6 text-gray-700 pb-10">
              <section>
                <h4 className="font-black text-gray-900 mb-2 uppercase text-xs tracking-widest">Data Collection</h4>
                <p className="text-sm leading-relaxed">
                  APKURL is designed with privacy at its core. We do not upload your APK files to our servers. All static analysis is performed locally on your device or via secure, ephemeral AI processing.
                </p>
              </section>
              <section>
                <h4 className="font-black text-gray-900 mb-2 uppercase text-xs tracking-widest">URL Scanning</h4>
                <p className="text-sm leading-relaxed">
                  When you scan a URL, the link is analyzed for phishing patterns. We do not track your browsing history or store personal information associated with these scans.
                </p>
              </section>
              <section>
                <h4 className="font-black text-gray-900 mb-2 uppercase text-xs tracking-widest">AI Analysis</h4>
                <p className="text-sm leading-relaxed">
                  Our AI models are trained to detect security threats. While highly accurate, they are not infallible. We recommend using APKURL as a supplementary tool in your security arsenal.
                </p>
              </section>
              <section>
                <h4 className="font-black text-gray-900 mb-2 uppercase text-xs tracking-widest">Local Storage</h4>
                <p className="text-sm leading-relaxed">
                  Your scan history is stored locally on your device. You have full control over this data and can delete it at any time from the History tab.
                </p>
              </section>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// --- Main App ---

const AppContent = () => {
  const location = useLocation();
  const showNav = ['/', '/history', '/settings'].includes(location.pathname);

  return (
    <div className="max-w-md mx-auto bg-white min-h-screen relative font-sans selection:bg-blue-100 selection:text-blue-900">
      <AnimatePresence mode="wait">
        <motion.div 
          key={location.pathname}
          initial={{ opacity: 0, x: 10 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -10 }}
          transition={{ duration: 0.2 }}
          className="min-h-screen"
        >
          <Routes location={location}>
            <Route path="/" element={<HomePage />} />
            <Route path="/scan-url" element={<ScanUrlPage />} />
            <Route path="/scanning" element={<ScanningPage />} />
            <Route path="/scan-apk" element={<ScanApkPage />} />
            <Route path="/result/:id" element={<ResultPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </motion.div>
      </AnimatePresence>
      
      {/* Bottom Nav is only shown on main tabs */}
      {showNav && <BottomNav />}
    </div>
  );
};

export default function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}
