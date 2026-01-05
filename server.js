require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const winston = require("winston");
const DailyRotateFile = require("winston-daily-rotate-file");
const app = express();

// Configuration du logger
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new DailyRotateFile({
      filename: `${process.env.LOG_DIR}/proxy-%DATE%.log`,
      datePattern: "YYYY-MM-DD",
      maxSize: "20m",
      maxFiles: "14d",
    }),
  ],
});

// Middleware de sécurité
app.use(helmet());
app.use(cors());

// Limite le débit pour éviter les abus
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS),
  max: parseInt(process.env.RATE_LIMIT_MAX),
  message: "Trop de requêtes, veuillez réessayer plus tard.",
});
app.use(limiter);

// Middleware pour vérifier la clé API
const authenticate = (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== process.env.API_KEY) {
    logger.warn(`Tentative d'accès non autorisée depuis ${req.ip}`);
    return res.status(403).json({ error: "Accès refusé : clé API invalide." });
  }
  next();
};

// Middleware pour valider le payload
const validatePayload = (req, res, next) => {
  if (!req.body.url || !req.body.title) {
    logger.warn(`Payload invalide depuis ${req.ip}`);
    return res.status(400).json({ error: "URL et titre sont requis." });
  }
  next();
};

// Middleware pour parser le JSON
app.use(express.json());

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "Proxy is running", timestamp: new Date().toISOString() });
});

// Route proxy
app.post("/proxy", authenticate, validatePayload, async (req, res) => {
  try {
    const { url, title } = req.body;
    logger.info(
      `Requête reçue depuis ${req.ip} | URL: ${url} | Titre: ${title}`
    );

    const response = await fetch(process.env.N8N_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, title }),
    });

    // Logs détaillés de la réponse
    logger.info(
      `Réponse de n8n: Status ${response.status} - ${response.statusText}`
    );

    if (!response.ok) {
      const errorDetails = await response.text(); // Récupère le corps de la réponse
      logger.error(`
        Erreur n8n depuis ${req.ip}:
        - Status: ${response.status}
        - StatusText: ${response.statusText}
        - Réponse: ${errorDetails}
        - Headers: ${JSON.stringify(response.headers)}
      `);
      throw new Error(`Erreur n8n: ${response.status} - ${errorDetails}`);
    }

    const responseData = await response.json(); // Optionnel: log la réponse réussie
    logger.info(`Succès n8n: ${JSON.stringify(responseData)}`);
    res.status(200).json({ success: true, data: responseData });
  } catch (error) {
    logger.error(`
      Erreur critique depuis ${req.ip}:
      - Message: ${error.message}
      - Stack: ${error.stack}
      - Requête: ${JSON.stringify({ url: req.body.url, title: req.body.title })}
    `);
    res.status(500).json({
      error: "Erreur interne du serveur.",
      details:
        process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
});

// Gestion des erreurs 404
app.use((req, res) => {
  res.status(404).json({ error: "Route non trouvée." });
});

// Démarrage du serveur
app.listen(process.env.PORT, () => {
  logger.info(`Proxy démarré sur le port ${process.env.PORT}`);
});
