const { Pool } = require('pg');
const bcrypt = require('bcryptjs');  // ← NOUVELLE LIGNE

// ── Connexion Neon PostgreSQL ──
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ... (reste du code inchangé) ...

module.exports = async (req, res) => {
    await dbReady;

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(200).end();

    const url    = req.url;
    const method = req.method;

    try {

        // ── LOGIN ──
        if (url.includes('/login') && method === 'POST') {
            const { email, password } = req.body;
            const result = await pool.query('SELECT * FROM users WHERE LOWER(email) = LOWER($1)', [email]);
            const user   = result.rows[0];

            // ✅ NOUVELLE LIGNE : Utiliser bcrypt.compare
            if (user && await bcrypt.compare(password, user.mot_de_passe)) {
                return res.json({
                    success: true,
                    user: { id: user.id, nom: user.nom, email: user.email, role: user.role }
                });
            }
            return res.status(401).json({ success: false, message: 'Email ou mot de passe incorrect' });
        }

        // ── REGISTER ──
        if (url.includes('/register') && method === 'POST') {
            const { nom, email, password, role } = req.body;

            if (!nom || !email || !password || !role) {
                return res.status(400).json({ success: false, message: 'Tous les champs sont obligatoires.' });
            }
            if (password.length < 6) {
                return res.status(400).json({ success: false, message: 'Mot de passe trop court (6 caractères min).' });
            }

            const existing = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
            if (existing.rows.length > 0) {
                return res.status(409).json({ success: false, message: 'Cet email est déjà utilisé.' });
            }

            // ✅ NOUVELLE LIGNE : Hacher le mot de passe
            const hashedPassword = await bcrypt.hash(password, 10);

            await pool.query(
                'INSERT INTO users (nom, email, mot_de_passe, role) VALUES ($1, $2, $3, $4)',
                [nom, email, hashedPassword, role]  // ← Utiliser hashedPassword
            );
            return res.json({ success: true, message: 'Compte créé avec succès.' });
        }

        // ... (reste du code inchangé) ...

    } catch (error) {
        console.error('API Error:', error);
        return res.status(500).json({ error: error.message });
    }
};