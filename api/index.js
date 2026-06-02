const { Pool }   = require('pg');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');

// ── Connexion Neon PostgreSQL ──
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ── Initialisation des tables + données de départ ──
async function initDB() {
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

    await pool.query(`
        CREATE TABLE IF NOT EXISTS audit_log (
            id SERIAL PRIMARY KEY,
            event TEXT,
            user_id INTEGER,
            ip TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    const count = await pool.query('SELECT COUNT(*) FROM users');
    if (parseInt(count.rows[0].count) === 0) {
        const hash = await bcrypt.hash('password123', 12);
        await pool.query(`
            INSERT INTO users (nom, email, mot_de_passe, role) VALUES
            ('Karim Alaoui', 'test@securetask.ma',  $1, 'Lead Securite'),
            ('Ahmad',        'ahmad@securetask.ma', $1, 'Ingenieur SSI'),
            ('Sara',         'sara@securetask.ma',  $1, 'Ingenieur SSI'),
            ('Laila',        'laila@securetask.ma', $1, 'Observateur')
        `, [hash]);
        console.log('✅ Utilisateurs initiaux créés avec mots de passe hachés');
    }
}

// Initialisation unique (mise en cache entre les invocations Vercel)
const dbReady = initDB().catch(err => console.error('❌ initDB error:', err));

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

function authMiddleware(req) {
    const header = req.headers['authorization'];
    if (!header) return null;
    const token = header.split(' ')[1];
    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
        return null;
    }
}

module.exports = async (req, res) => {
    await dbReady;

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    if (req.method === 'OPTIONS') return res.status(200).end();

    const url    = req.url;
    const method = req.method;
    const ip     = req.headers['x-forwarded-for'] || 'unknown';

    try {

        // ── LOGIN ──
        if (url.includes('/login') && method === 'POST') {
            const { email, password } = req.body;
            const result = await pool.query(
                'SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]
            );
            const user = result.rows[0];
            const ok   = user && await bcrypt.compare(password, user.mot_de_passe);

            if (ok) {
                const token = jwt.sign(
                    { id: user.id, role: user.role, email: user.email, nom: user.nom },
                    process.env.JWT_SECRET,
                    { expiresIn: '8h' }
                );
                await logEvent('LOGIN_OK', user.id, ip, user.email);
                return res.json({ success: true, token });
            }
            await logEvent('LOGIN_FAIL', null, ip, email);
            return res.status(401).json({ success: false, message: 'Email ou mot de passe incorrect' });
        }

        // ── REGISTER ──
        if (url.includes('/register') && method === 'POST') {
            const { nom, email, password, role, codeAcces } = req.body;

            if (!codeAcces || codeAcces.toUpperCase() !== process.env.ACCESS_CODE) {
                return res.status(403).json({ success: false, message: "Code d'accès invalide." });
            }

            if (!nom || !email || !password || !role) {
                return res.status(400).json({ success: false, message: 'Tous les champs sont obligatoires.' });
            }
            if (password.length < 6) {
                return res.status(400).json({ success: false, message: 'Mot de passe trop court (6 caractères min).' });
            }

            const existing = await pool.query(
                'SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]
            );
            if (existing.rows.length > 0) {
                return res.status(409).json({ success: false, message: 'Cet email est déjà utilisé.' });
            }

            const hash = await bcrypt.hash(password, 12);
            await pool.query(
                'INSERT INTO users (nom, email, mot_de_passe, role) VALUES ($1, $2, $3, $4)',
                [nom, email, hash, role]
            );
            await logEvent('REGISTER', null, ip, email);
            return res.json({ success: true, message: 'Compte créé avec succès.' });
        }

        // ── Routes protégées : vérification du token ──
        const user = authMiddleware(req);
        if (!user) {
            return res.status(401).json({ error: 'Non connecté — token manquant ou invalide' });
        }

        // ── GET TÂCHES ──
        if (url.includes('/taches') && method === 'GET' && !url.match(/\/taches\/\d+/)) {
            const result = await pool.query('SELECT * FROM taches ORDER BY created_at DESC');
            return res.json(result.rows);
        }

        // ── CREATE TÂCHE (Lead ou Ingénieur SSI) ──
        if (url.includes('/taches') && method === 'POST') {
            if (!['Lead Securite', 'Ingenieur SSI'].includes(user.role)) {
                return res.status(403).json({ error: 'Accès refusé — rôle insuffisant' });
            }
            const { titre, description, priorite, echeance, assigneA, statut, labels } = req.body;
            const result = await pool.query(
                `INSERT INTO taches (titre, description, priorite, echeance, assigne_a, statut, labels)
                 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
                [
                    titre,
                    description || '',
                    priorite    || 'Moyenne',
                    echeance    || '',
                    assigneA    || 'Non assigne',
                    statut      || 'A faire',
                    (labels || []).join(', ')
                ]
            );
            await logEvent('CREATE_TASK', user.id, ip, `Tâche: ${titre}`);
            return res.json({ success: true, id: result.rows[0].id });
        }

        // ── UPDATE TÂCHE (Lead ou Ingénieur SSI) ──
        if (url.match(/\/taches\/\d+/) && method === 'PUT') {
            if (!['Lead Securite', 'Ingenieur SSI'].includes(user.role)) {
                return res.status(403).json({ error: 'Accès refusé — rôle insuffisant' });
            }
            const id = url.split('/').pop();
            await pool.query('UPDATE taches SET statut = $1 WHERE id = $2', [req.body.statut, id]);
            return res.json({ success: true });
        }

        // ── DELETE TÂCHE (Lead Securite seulement) ──
        if (url.match(/\/taches\/\d+/) && method === 'DELETE') {
            if (user.role !== 'Lead Securite') {
                return res.status(403).json({ error: 'Accès refusé — rôle insuffisant' });
            }
            const id = url.split('/').pop();
            await pool.query('DELETE FROM taches WHERE id = $1', [id]);
            await logEvent('DELETE_TASK', user.id, ip, `ID: ${id}`);
            return res.json({ success: true });
        }

        // ── GET USERS (Lead ou Ingénieur SSI) ──
        if (url.includes('/users') && method === 'GET') {
            if (!['Lead Securite', 'Ingenieur SSI'].includes(user.role)) {
                return res.status(403).json({ error: 'Accès refusé — rôle insuffisant' });
            }
            const result = await pool.query('SELECT id, nom, email, role FROM users');
            return res.json(result.rows);
        }

        return res.status(404).json({ error: 'Route non trouvée' });

    } catch (error) {
        console.error('API Error:', error);
        return res.status(500).json({ error: error.message });
    }
};