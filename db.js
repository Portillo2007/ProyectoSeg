require("dotenv").config();
const { MongoClient } = require("mongodb");

const client = new MongoClient(process.env.MONGODB_URI);

let db;

const connectDB = async () => {
    try {
        await client.connect();
        db = client.db(process.env.DB_NAME || "proyecto");
        console.log("Conexión exitosa a MongoDB Atlas");
    } catch (error) {
        console.error("Error conectando a MongoDB Atlas:", error);
        process.exit(1);
    }
};

const getDB = () => {
    if (!db) {
        throw new Error("Base de datos no conectada. Llama a connectDB() primero.");
    }
    return db;
};

module.exports = { client, connectDB, getDB };
