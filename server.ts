import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import ApkReader from "adbkit-apkreader";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const upload = multer({ dest: process.env.VERCEL ? '/tmp' : 'uploads/' });

async function createServer() {
  const app = express();
  const PORT = 3000;

  // Ensure uploads directory exists and is writable (only for local dev)
  if (!process.env.VERCEL) {
    if (!fs.existsSync('uploads')) {
      fs.mkdirSync('uploads', { recursive: true });
    }
  }

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  
  // Log all requests
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
  });

  const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;

  if (VT_API_KEY) {
    console.log("VirusTotal API Key loaded successfully.");
  } else {
    console.warn("VirusTotal API Key is missing. Scanning will be limited to local heuristics.");
  }

  // API routes
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", timestamp: Date.now() });
  });

  app.get("/api/config/status", (req, res) => {
    res.json({
      virustotal: !!VT_API_KEY,
      gemini: !!process.env.GEMINI_API_KEY
    });
  });

  // APK Analysis
  app.post("/api/apk/analyze", upload.single('apk'), async (req, res) => {
    console.log("Received APK analysis request");
    if (!req.file) {
      console.error("No APK file uploaded in request");
      return res.status(400).json({ error: "No APK file uploaded" });
    }

    const filePath = req.file.path;
    console.log(`Analyzing APK at: ${filePath}`);
    try {
      const reader = await ApkReader.open(filePath);
      const manifest = await reader.readManifest();
      
      console.log("Manifest extracted successfully for package:", manifest.package);
      
      // Clean up uploaded file
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      
      res.json({
        packageName: manifest.package,
        versionName: manifest.versionName,
        versionCode: manifest.versionCode,
        permissions: manifest.usesPermissions?.map((p: any) => p.name) || [],
      });
    } catch (error) {
      console.error("APK Analysis Error:", error);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      res.status(500).json({ error: "Failed to analyze APK manifest" });
    }
  });

  app.get("/api/vt/url/:id", async (req, res) => {
    if (!VT_API_KEY) {
      return res.status(503).json({ error: "VIRUSTOTAL_API_KEY not configured" });
    }

    try {
      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${req.params.id}`, {
        headers: { 'x-apikey': VT_API_KEY }
      });

      console.log(`VirusTotal URL API Response: ${response.status} ${response.statusText}`);

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          console.error("VirusTotal API Key is invalid or unauthorized.");
        }
        return res.status(response.status).json({ error: response.statusText });
      }

      const data = await response.json();
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: "Internal Server Error" });
    }
  });

  app.get("/api/vt/file/:hash", async (req, res) => {
    if (!VT_API_KEY) {
      return res.status(503).json({ error: "VIRUSTOTAL_API_KEY not configured" });
    }

    try {
      const response = await fetch(`https://www.virustotal.com/api/v3/files/${req.params.hash}`, {
        headers: { 'x-apikey': VT_API_KEY }
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: response.statusText });
      }

      const data = await response.json();
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: "Internal Server Error" });
    }
  });

  // Gemini AI Analysis
  app.post("/api/analyze-summary", async (req, res) => {
    const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
    if (!GEMINI_API_KEY) {
      return res.status(503).json({ error: "GEMINI_API_KEY not configured" });
    }

    const { scan } = req.body;
    if (!scan) {
      return res.status(400).json({ error: "No scan data provided" });
    }

    try {
      const { GoogleGenAI } = await import("@google/genai");
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

      res.json(JSON.parse(responseText));
    } catch (error) {
      console.error("Gemini Analysis Error:", error);
      res.status(500).json({ error: "Failed to generate AI summary" });
    }
  });

  // Vite middleware for development (only if not on Vercel)
  if (!process.env.VERCEL) {
    if (process.env.NODE_ENV !== "production") {
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: "spa",
      });
      app.use(vite.middlewares);
    } else {
      const distPath = path.join(process.cwd(), 'dist');
      app.use(express.static(distPath));
      app.get('*all', (req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  return app;
}

// For local development
if (!process.env.VERCEL) {
  createServer().then(app => {
    app.listen(3000, "0.0.0.0", () => {
      console.log(`Server running on http://localhost:3000`);
    });
  });
}

// Export for Vercel
export default async (req: any, res: any) => {
  const app = await createServer();
  return app(req, res);
};
