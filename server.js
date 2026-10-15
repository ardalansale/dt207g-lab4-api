const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 3000;
const hemligNyckel = 'superduperhemligt123'; // Enkel hemlig nyckel för JWT

// Middleware (hjälpmedel för servern)
app.use(express.json()); // Gör så servern kan läsa JSON-data från formulär
app.use(cors());         // Gör så din webbplats kan prata med servern

// Skapar filen "databas.db" automatiskt
const db = new sqlite3.Database('./databas.db', (fel) => {
    if (fel) {
        console.log('Kunde inte ansluta till databasen:', fel.message);
    } else {
        console.log('Ansluten till databasen!');
    }
});

// Obs. Skapa tabell för användare om den inte finns
db.run(`CREATE TABLE IF NOT EXISTS anvandare (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)`);


// 1. Registrera ny användare
app.post('/api/register', async (req, res) => {
    const anandarnamn = req.body.username;
    const losenord = req.body.password;

    // Enkel kontroll att fälten inte är tomma
    if (!anandarnamn || !losenord) {
        return res.status(400).json({ fel: 'Du måste fylla i både användarnamn och lösenord!' });
    }

    try {
        // Kryptera clösenordet (så det inte sparas i text)
        const hashTimer = 10;
        const hashLosen = await bcrypt.hash(losenord, hashTimer);

        // Spara till databasen
        const sql = `INSERT INTO anvandare (username, password) VALUES (?, ?)`;
        db.run(sql, [anandarnamn, hashLosen], (fel) => {
            if (fel) {
                return res.status(400).json({ fel: 'Användarnamnet är redan upptaget.' });
            }
            res.status(201).json({ meddelande: 'Kontot är skapat!' });
        });

    } catch (err) {
        res.status(500).json({ fel: 'Ett serverfel uppstod.' });
    }
});

// 2. Logga in 
app.post('/api/login', (req, res) => {
    const anandarnamn = req.body.username;
    const losenord = req.body.password;

    if (!anandarnamn || !losenord) {
        return res.status(400).json({ fel: 'Fyll i användarnamn och lösenord.' });
    }

    // Leta efter användaren i databasen
    const sql = `SELECT * FROM anvandare WHERE username = ?`;
    db.get(sql, [anandarnamn], async (fel, anvandare) => {
        if (fel || !anvandare) {
            return res.status(401).json({ fel: 'Felaktigt användarnamn eller lösenord.' });
        }

        const losenordStämmer = await bcrypt.compare(losenord, anvandare.password);
        if (!losenordStämmer) {
            return res.status(401).json({ fel: 'Felaktigt användarnamn eller lösenord.' });
        }

        // Skapa en JWT-token
        const token = jwt.sign(
            { id: anvandare.id, username: anvandare.username }, 
            hemligNyckel, 
            { expiresIn: '1h' }
        );

        //
        res.json({
            meddelande: 'Inloggning lyckades!',
            token: token
        });
    });
});


//  Kolla om JWT-token är giltig
function kollaToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    
    // Token skickas med som "Bearer <token>"
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ fel: 'Ingen token medföljer. Åtkomst nekad!' });
    }

    jwt.verify(token, hemligNyckel, (fel, anvandare) => {
        if (fel) {
            return res.status(403).json({ fel: 'Ogiltig eller utgången token.' });
        }
        req.anvandare = anvandare;
        next();
    });
}


// 3. Skyddad route (kräver inlog)
app.get('/api/skyddad', kollaToken, (req, res) => {
    // Hämta data från databasen att visa
    db.all(`SELECT id, username FROM anvandare`, [], (fel, rader) => {
        if (fel) {
            return res.status(500).json({ fel: 'Kunde inte hämta data.' });
        }

        res.json({
            meddelande: 'Du hittat den hemliga sidan!',
            inloggadSom: req.anvandare.username,
            allaRegistrerade: rader
        });
    });
});