import express from "express";
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
  const PORT = process.env.PORT || 3000;

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
      gemini: !!(process.env.VITE_GEMINI_API_KEY || process.env.GEMINI_API_KEY)
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
      const vtUrl = `https://www.virustotal.com/api/v3/urls/${req.params.id}`;
      console.log(`[VT URL] API key prefix: ${VT_API_KEY.substring(0, 10)}`);
      console.log(`[VT URL] Requesting: ${vtUrl}`);

      const response = await fetch(vtUrl, {
        headers: { 'x-apikey': VT_API_KEY }
      });

      console.log(`[VT URL] Response status: ${response.status} ${response.statusText}`);
      console.log(`[VT URL] Response headers: ${JSON.stringify(Object.fromEntries(response.headers.entries()))}`);

      const responseBody = await response.text();
      console.log(`[VT URL] Response body: ${responseBody}`);

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          console.error("VirusTotal API Key is invalid or unauthorized.");
        }
        return res.status(response.status).json({ error: response.statusText });
      }

      res.json(JSON.parse(responseBody));
    } catch (error) {
      res.status(500).json({ error: "Internal Server Error" });
    }
  });

  app.get("/api/vt/file/:hash", async (req, res) => {
    if (!VT_API_KEY) {
      return res.status(503).json({ error: "VIRUSTOTAL_API_KEY not configured" });
    }

    try {
      const vtUrl = `https://www.virustotal.com/api/v3/files/${req.params.hash}`;
      console.log(`[VT FILE] API key prefix: ${VT_API_KEY.substring(0, 10)}`);
      console.log(`[VT FILE] Requesting: ${vtUrl}`);

      const response = await fetch(vtUrl, {
        headers: { 'x-apikey': VT_API_KEY }
      });

      console.log(`[VT FILE] Response status: ${response.status} ${response.statusText}`);
      console.log(`[VT FILE] Response headers: ${JSON.stringify(Object.fromEntries(response.headers.entries()))}`);

      const responseBody = await response.text();
      console.log(`[VT FILE] Response body: ${responseBody}`);

      if (!response.ok) {
        return res.status(response.status).json({ error: response.statusText });
      }

      res.json(JSON.parse(responseBody));
    } catch (error) {
      res.status(500).json({ error: "Internal Server Error" });
    }
  });

  // Vite middleware for development (only if not on Vercel)
  if (!process.env.VERCEL && process.env.NODE_ENV !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else if (!process.env.VERCEL) {
    // Local production mode
    const distPath = path.join(process.cwd(), 'dist');
    if (fs.existsSync(distPath)) {
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
    const port = Number(process.env.PORT) || 3000;
    app.listen(port, "0.0.0.0", () => {
      console.log(`Server running on port ${port}`);
    });
  });
}

// Export for Vercel
export default async (req: any, res: any) => {
  const app = await createServer();
  return app(req, res);
};
