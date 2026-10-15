const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 3000;
const secretKey = 'superdupersecret123'; // Enkel hemlig nyckel för JWT

// Middleware (hjälpmedel för servern)
app.use(express.json()); // Gör så servern kan läsa JSON-data från formulär
app.use(cors());         // Gör så din webbplats kan prata med servern

// Skapar filen "database.db" automatiskt
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.log('Kunde inte ansluta till databasen:', err.message);
    } else {
        console.log('Ansluten till databasen!');
    }
});

// Skapa tabell för användare om den inte finns
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)`);


// 1. Registrera ny användare
app.post('/api/register', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // Enkel kontroll att fälten inte är tomma
    if (!username || !password) {
        return res.status(400).json({ error: 'Du måste fylla i både användarnamn och lösenord!' });
    }

    try {
        // Kryptera lösenordet (så det inte sparas i klartext)
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Spara till databasen
        const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
        db.run(sql, [username, hashedPassword], (err) => {
            if (err) {
                return res.status(400).json({ error: 'Användarnamnet är redan upptaget.' });
            }
            res.status(201).json({ message: 'Kontot är skapat!' });
        });

    } catch (error) {
        res.status(500).json({ error: 'Ett serverfel uppstod.' });
    }
});


// 2. Logga in
app.post('/api/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    if (!username || !password) {
        return res.status(400).json({ error: 'Fyll i användarnamn och lösenord.' });
    }

    // Leta efter användaren i databasen
    const sql = `SELECT * FROM users WHERE username = ?`;
    db.get(sql, [username], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Felaktigt användarnamn eller lösenord.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Felaktigt användarnamn eller lösenord.' });
        }

        // Skapa en JWT-token
        const token = jwt.sign(
            { id: user.id, username: user.username }, 
            secretKey, 
            { expiresIn: '1h' }
        );

        res.json({
            message: 'Inloggning lyckades!',
            token: token
        });
    });
});


// Hjälpfunktion för att kolla om JWT-token är giltig
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    
    // Token skickas med som "Bearer <token>"
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
app.get('/api/protected', verifyToken, (req, res) => {
    // Hämta data från databasen att visa
    db.all(`SELECT id, username FROM users`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Kunde inte hämta data.' });
        }

        res.json({
            message: 'Du har hittat den hemliga sidan!',
            loggedInAs: req.user.username,
            allRegisteredUsers: rows
        });
    });
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});