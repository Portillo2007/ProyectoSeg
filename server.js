require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const mongoSanitize = require("mongo-sanitize");
const { connectDB, getDB } = require("./db");
const path = require("path");
const { ObjectId } = require("mongodb");

const app = express();

// Configurar trust proxy para rate limiting
app.set('trust proxy', 1);

// Middleware de seguridad
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            connectSrc: ["'self'", "'unsafe-inline'"]
        }
    }
}));

// CORS dinámico para ngrok
app.use(cors({
    origin: function (origin, callback) {
        // Permitir localhost y cualquier URL ngrok
        if (!origin) return callback(null, true);
        if (origin.includes('localhost') || origin.includes('ngrok')) {
            return callback(null, true);
        }
        callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Sanitización contra NoSQL Injection
app.use((req, res, next) => {
    if (req.body) req.body = mongoSanitize(req.body);
    if (req.query) req.query = mongoSanitize(req.query);
    if (req.params) req.params = mongoSanitize(req.params);
    next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const SECRET_KEY = process.env.SECRET_KEY;
const PORT = process.env.PORT || 3000;

// Servir archivos estáticos
app.use(express.static(path.join(__dirname)));

// Rate limiting global
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Demasiadas solicitudes, intenta más tarde",
    standardHeaders: true,
    legacyHeaders: false
});

// Rate limiting específico para login
const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 5,
    message: "Demasiados intentos de login, intenta en 1 minuto",
    skipSuccessfulRequests: true
});

// Rate limiting para registro
const registerLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3,
    message: "Demasiados registros, intenta más tarde"
});

app.use(globalLimiter);
app.use("/login", loginLimiter);
app.use("/register", registerLimiter);

// Validación de contraseña
function validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    return password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar;
}

// Validación de ObjectId
function isValidObjectId(id) {
    return ObjectId.isValid(id) && new ObjectId(id).toString() === id;
}

// Middleware de manejo de errores
function errorHandler(err, req, res, next) {
    console.error(`Error ${err.status || 500}:`, err.message);
    
    if (process.env.NODE_ENV === 'production') {
        res.status(err.status || 500).json({
            ok: false,
            msg: 'Error interno del servidor'
        });
    } else {
        res.status(err.status || 500).json({
            ok: false,
            msg: err.message || 'Error interno del servidor'
        });
    }
}

// ===== REGISTRO =====
app.post("/register", 
    [
        body('username')
            .isLength({ min: 3, max: 30 })
            .matches(/^[a-zA-Z0-9_]+$/)
            .withMessage('Username debe tener 3-30 caracteres alfanuméricos'),
        body('password')
            .custom((value) => {
                if (!validatePassword(value)) {
                    throw new Error('Password debe tener 8+ caracteres, mayúsculas, minúsculas, números y caracteres especiales');
                }
                return true;
            })
    ],
    async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                ok: false,
                msg: 'Datos inválidos',
                errors: errors.array()
            });
        }

        const { username, password } = req.body;

        try {
            const db = getDB();
            const exists = await db.collection("users").findOne({ username: username.toLowerCase().trim() });
            if (exists) {
                return res.status(409).json({ ok: false, msg: "Usuario ya existe" });
            }

            const hashed = bcrypt.hashSync(password, 12);
            await db.collection("users").insertOne({ 
                username: username.toLowerCase().trim(), 
                password_hash: hashed,
                created_at: new Date()
            });
            
            res.status(201).json({ ok: true, msg: "Usuario registrado correctamente" });
        } catch (err) {
            next(err);
        }
    }
);

// ===== LOGIN =====
app.post("/login", 
    [
        body('username').trim().isLength({ min: 1 }).withMessage('Username requerido'),
        body('password').isLength({ min: 1 }).withMessage('Password requerido')
    ],
    async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                ok: false,
                msg: 'Datos inválidos',
                errors: errors.array()
            });
        }

        const { username, password } = req.body;
        
        try {
            const db = getDB();
            const user = await db.collection("users").findOne({ username: username.toLowerCase().trim() });
            if (!user) {
                return res.status(401).json({ ok: false, msg: "Credenciales inválidas" });
            }

            const valid = bcrypt.compareSync(password, user.password_hash);
            if (!valid) {
                return res.status(401).json({ ok: false, msg: "Credenciales inválidas" });
            }

            const token = jwt.sign(
                { username: user.username, id: user._id.toString() }, 
                SECRET_KEY, 
                { expiresIn: "30m" } // Reducir a 30 minutos
            );
            
            res.json({ ok: true, msg: "Login correcto", token, userId: user._id.toString() });
        } catch (err) {
            next(err);
        }
    }
);

// ===== MIDDLEWARE DE TOKEN =====
function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
        return res.status(403).json({ msg: "Token requerido" });
    }
    
    // Aceptar ambos formatos: Bearer token y token directo
    const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader;
    
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        // Verificar si el token es reciente (opcional: para invalidar sesiones anteriores)
        const now = Date.now();
        const tokenIssuedAt = decoded.iat * 1000;
        const maxAge = 30 * 60 * 1000; // 30 minutos
        
        if (now - tokenIssuedAt > maxAge) {
            return res.status(401).json({ msg: "Sesión expirada por inactividad" });
        }
        
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ msg: "Token inválido o expirado" });
    }
}

// ===== GUARDAR TEXTO CIFRADO =====
app.post("/save-text", verifyToken, 
    [
        body('cipher').isLength({ min: 1, max: 10000 }).withMessage('Cipher requerido y máximo 10k caracteres')
    ],
    async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                ok: false,
                msg: 'Datos inválidos',
                errors: errors.array()
            });
        }

        const { cipher } = req.body;

        try {
            if (!isValidObjectId(req.user.id)) {
                return res.status(400).json({ ok: false, msg: "ID de usuario inválido" });
            }

            const db = getDB();
            await db.collection("texts").insertOne({
                user_id: new ObjectId(req.user.id),
                cipher: cipher.trim(),
                created_at: new Date()
            });
            
            res.status(201).json({ ok: true, msg: "Texto guardado" });
        } catch (err) {
            next(err);
        }
    }
);

// ===== OBTENER TEXTOS CIFRADOS =====
app.get("/my-texts", verifyToken, async (req, res, next) => {
    try {
        if (!isValidObjectId(req.user.id)) {
            return res.status(400).json({ ok: false, msg: "ID de usuario inválido" });
        }

        const db = getDB();
        const result = await db.collection("texts")
            .find({ user_id: new ObjectId(req.user.id) })
            .sort({ created_at: -1 })
            .limit(100) // Limitar resultados
            .toArray();
            
        res.json({ ok: true, rows: result });
    } catch (err) {
        next(err);
    }
});

// Middleware de manejo de errores
app.use(errorHandler);

// Servir index.html en la raíz
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// Conectar a MongoDB Atlas
connectDB().then(() => {
    app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
});
