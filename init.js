require("dotenv").config();
const { pool } = require("./db");

async function createTables() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS texts (
                id SERIAL PRIMARY KEY,
                user_id INT REFERENCES users(id),
                cipher TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log("Tablas creadas correctamente en MongoDB Atlas");
        process.exit(0);
    } catch (err) {
        console.error("Error creando tablas:", err);
        process.exit(1);
    }
}

createTables();
