const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: '.env.local' });

const express = require('express');
const { Pool } = require('pg');
const path = require('path');

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Connexion Neon PostgreSQL ──

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
});
console.log('DB URL:', process.env.DATABASE_URL)
pool.connect()
    .then(() => console.log('✅ Connected to Neon PostgreSQL'))
    .catch(err => console.error('❌ Database connection error:', err));

// ── Création des tables PostgreSQL ──

async function initDB() {
    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                nom TEXT,
                email TEXT UNIQUE,
                mot_de_passe TEXT,
                role TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS taches (
                id SERIAL PRIMARY KEY,
                titre TEXT,
                description TEXT,
                priorite TEXT,
                echeance TEXT,
                assigne_a TEXT,
                statut TEXT,
                labels TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        const result = await pool.query(
            'SELECT COUNT(*) FROM users'
        );

        if (parseInt(result.rows[0].count) === 0) {

           const h = await bcrypt.hash('password123', 12);

            await pool.query(
            `INSERT INTO users (nom, email, mot_de_passe, role)
            VALUES
            ('Karim Alaoui', 'test@securetask.ma',  $1, 'Lead Securite'),
            ('Ahmad',        'ahmad@securetask.ma', $1, 'Ingenieur SSI'),
            ('Sara',         'sara@securetask.ma',  $1, 'Ingenieur SSI'),
            ('Laila',        'laila@securetask.ma', $1, 'Observateur')`,
            [h]
            );

            console.log('✅ Utilisateurs initiaux créés avec mots de passe hachés !');

    } } catch (error) {
        console.error('❌ Erreur init DB :', error);
    }
}

initDB();
function authMiddleware(req, res, next) {
    const header = req.headers['authorization'];
    if (!header) {
        return res.status(401).json({ error: 'Non connecté — token manquant' });
    }
    const token = header.split(' ')[1];
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Token invalide ou expiré' });
    }
}
function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Non authentifié' });
        }
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Accès refusé — rôle insuffisant' });
        }
        next();
    };
}
async function logEvent(event, userId, ip, details) {
    try {
        await pool.query(
            'INSERT INTO audit_log (event, user_id, ip, details) VALUES ($1, $2, $3, $4)',
            [event, userId || null, ip, details]
        );
    } catch (e) {
        console.error('Erreur audit log:', e);
    }
}

// ── Routes API ──

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'connexion.html'));
});

// ── LOGIN ──

app.post('/api/login', async (req, res) => {

    try {

        const { email, password } = req.body;

        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        const user = result.rows[0];

        const motDePasseCorrect = user && await bcrypt.compare(password, user.mot_de_passe);
        if (motDePasseCorrect) {
            await logEvent('LOGIN_OK', user.id, req.ip, user.email);
            return res.json({
                success: true,
                user: {
                    id: user.id,
                    nom: user.nom,
                    email: user.email,
                    role: user.role
                }
            });
        }
        await logEvent('LOGIN_FAIL', null, req.ip, email);
        res.status(401).json({
            success: false,
            message: 'Email ou mot de passe incorrect'
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// ── REGISTER ──

app.post('/api/register', async (req, res) => {

    try {

        const { nom, email, password, codeAcces } = req.body;

        // Loi 5 — vérification du code d'accès côté serveur
        if (!codeAcces || codeAcces.toUpperCase() !== process.env.ACCESS_CODE) {
            return res.status(403).json({ success: false, message: "Code d'accès invalide." });
        }

        if (!nom || !email || !password) {

            return res.status(400).json({
                success: false,
                message: 'Tous les champs sont obligatoires.'
            });
        }

        if (password.length < 6) {

            return res.status(400).json({
                success: false,
                message: 'Mot de passe trop court.'
            });
        }

        const existing = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        );

        if (existing.rows.length > 0) {

            return res.status(409).json({
                success: false,
                message: 'Cet email est déjà utilisé.'
            });
        }

       const hash = await bcrypt.hash(password, 12);
       await pool.query('INSERT INTO users (nom, email, mot_de_passe, role) VALUES ($1, $2, $3, $4)',
       [nom, email, hash, 'Utilisateur']);
       await logEvent('REGISTER', null, req.ip, email);
        res.json({
            success: true,
            message: 'Compte créé avec succès.'
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message: 'Erreur serveur'
        });
    }
});

// ── TACHES ──

app.get('/api/taches',        authMiddleware, async (req, res) => {

    try {

        const result = await pool.query(
            'SELECT * FROM taches ORDER BY created_at DESC'
        );

        res.json(result.rows);

    } catch (error) {

        res.status(500).json({
            error: error.message
        });
    }
});

// Créer une tâche : Lead ou Ingénieur SSI seulement
app.post('/api/taches',
    authMiddleware,
    requireRole('Lead Securite', 'Ingenieur SSI'),
    async (req, res) => {

    try {

        const {
            titre,
            description,
            priorite,
            echeance,
            assigneA,
            statut,
            labels
        } = req.body;

        const result = await pool.query(
            `
            INSERT INTO taches
            (titre, description, priorite, echeance, assigne_a, statut, labels)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            `,
            [
                titre,
                description || '',
                priorite || 'Moyenne',
                echeance,
                assigneA || 'Non assigne',
                statut || 'A faire',
                (labels || []).join(', ')
            ]
        );
        await logEvent('CREATE_TASK', req.user.id, req.ip, `Tâche: ${titre}`);
        res.json({
            success: true,
            id: result.rows[0].id
        });

    } catch (error) {

        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Modifier une tâche : Lead ou Ingénieur SSI seulement
app.put('/api/taches/:id',
    authMiddleware,
    requireRole('Lead Securite', 'Ingenieur SSI'),
    async (req, res) => {

    try {

        await pool.query(
            'UPDATE taches SET statut = $1 WHERE id = $2',
            [req.body.statut, req.params.id]
        );

        res.json({
            success: true
        });

    } catch (error) {

        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Supprimer une tâche : Lead Securite seulement
app.delete('/api/taches/:id',
    authMiddleware,
    requireRole('Lead Securite'),
    async (req, res) => {
    try {

        await pool.query(
            'DELETE FROM taches WHERE id = $1',
            [req.params.id]
        );
        await logEvent('DELETE_TASK', req.user.id, req.ip, `ID: ${req.params.id}`);
        res.json({
            success: true
        });

    } catch (error) {

        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ── USERS ──

// Voir la liste des utilisateurs : Lead seulement
app.get('/api/users',
    authMiddleware,
    requireRole('Lead Securite', 'Ingenieur SSI'),
    async (req, res) => {
    try {

        const result = await pool.query(
            'SELECT id, nom, email, role FROM users'
        );

        res.json(result.rows);

    } catch (error) {

        res.status(500).json({
            error: error.message
        });
    }
});

// ── PORT ──

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
    console.log(`✅ SecureTask démarré sur le port ${PORT}`);
});