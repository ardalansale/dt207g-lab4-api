# DT207G – Laboration 4 – Autentisering i webbtjänst
En REST API-webbtjänst byggd med Node.js och Express som hanterar användarregistrering, lösenordskryptering och säker inloggning med hjälp av JWT (JSON Web Tokens) och SQLite.

## GitHub-repo
https://github.com/ardalansale/dt207g-lab-backend

## Funktionalitet
- **`POST /api/register`** – Registrerar en ny användare med säkert krypterat lösenord (`bcrypt`).
- **`POST /api/login`** – Loggar in användaren och returnerar en genererad JWT-token.
- **`GET /api/protected`** – En skyddad ändpunkt som kräver en giltig Bearer-token för att hämta data från databasen.
- CORS-stöd för att tillåta anrop från klientwebbplatsen.

## Komponenter och struktur
- `server.js` – Huvudfil för Express-servern, rutter, middleware och databasanrop.
- `database.db` – Lokal SQLite-databas som skapas automatiskt.
- `package.json` – Hanterar projektets beroenden (Express, sqlite3, bcrypt, jsonwebtoken, cors).

## Tekniker
- Node.js
- Express.js
- SQLite3
- bcrypt
- jsonwebtoken (JWT)
- CORS

## Körning
1. Klona repot och installera beroenden med `npm install`.
2. Starta servern lokalt med `node server.js` (eller `npm start`). Servern körs som standard på `http://localhost:3000`.