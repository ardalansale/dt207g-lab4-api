const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;
const secretKey = 'superdupersecret123'; // Enkel hemlig nyckel för JWT

// Middleware
app.use(express.json());
app.use(cors());

// Anslutning till Neon (PostgreSQL) via DATABASE_URL miljövariabel
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Krävs för att ansluta säkert till molnet
    }
});

// Skapa tabell för användare om den inte finns
async function initDb() {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )`);
        console.log('Ansluten till Neon-databasen och tabell kontrollerad!');
    } catch (err) {
        console.log('Kunde inte ansluta till databasen:', err.message);
    }
}
initDb();

// 1. Registrera ny användare
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Du måste fylla i både användarnamn och lösenord!' });
    }

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        await pool.query(
            `INSERT INTO users (username, password) VALUES ($1, $2)`,
            [username, hashedPassword]
        );

        res.status(201).json({ message: 'Kontot är skapat!' });
    } catch (err) {
        // PostgreSQL felkod 23505 betyder att unikt värde (username) redan finns
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Användarnamnet är redan upptaget.' });
        }
        res.status(500).json({ error: 'Ett serverfel uppstod.' });
    }
});

// 2. Logga in
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Fyll i användarnamn och lösenord.' });
    }

    try {
        const result = await pool.query(`SELECT * FROM users WHERE username = $1`, [username]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Felaktigt användarnamn eller lösenord.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Felaktigt användarnamn eller lösenord.' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username }, 
            secretKey, 
            { expiresIn: '1h' }
        );

        res.json({
            message: 'Inloggning lyckades!',
            token: token
        });
    } catch (err) {
        res.status(500).json({ error: 'Ett serverfel uppstod vid inloggning.' });
    }
});

// Hjälpfunktion för att kolla om JWT-token är giltig
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Ingen token medföljer. Åtkomst nekad!' });
    }

    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Ogiltig eller utgången token.' });
        }
        req.user = user;
        next();
    });
}

// 3. Skyddad route (kräver inloggning)
app.get('/api/protected', verifyToken, async (req, res) => {
    try {
        const result = await pool.query(`SELECT id, username FROM users`);

        res.json({
            message: 'Du har hittat den hemliga sidan!',
            loggedInAs: req.user.username,
            allRegisteredUsers: result.rows
        });
    } catch (err) {
        res.status(500).json({ error: 'Kunde inte hämta data.' });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});