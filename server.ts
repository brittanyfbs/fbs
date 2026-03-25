import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import ApkReader from "apkreader";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const upload = multer({ dest: 'uploads/' });

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;

  if (VT_API_KEY) {
    console.log("VirusTotal API Key loaded successfully.");
  } else {
    console.warn("VirusTotal API Key is missing. Scanning will be limited to local heuristics.");
  }

  // API routes
  app.get("/api/config/status", (req, res) => {
    res.json({
      virustotal: !!VT_API_KEY,
      gemini: !!process.env.GEMINI_API_KEY
    });
  });

  // APK Analysis
  app.post("/api/apk/analyze", upload.single('apk'), async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "No APK file uploaded" });
    }

    const filePath = req.file.path;
    try {
      const reader = await ApkReader.open(filePath);
      const manifest = await reader.readManifest();
      
      // Clean up uploaded file
      fs.unlinkSync(filePath);
      
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

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
