const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

app.post('/usuarios', async (req, res) => {
    console.log('Solicitud de registro recibida');
    try {
        const { email, password, rol, lenguaje } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO usuarios (email, password, rol, lenguaje) VALUES ($1, $2, $3, $4)',
            [email, hashedPassword, rol, lenguaje]
        );
        res.status(201).json({ message: 'Usuario registrado con éxito' });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: 'Error del servidor' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Contraseña incorrecta' });
        }
        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, {
            expiresIn: '1h',
        });
        res.json({ token });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: 'Error del servidor' });
    }
});

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        console.log('Token no proporcionado');
        return res.status(401).json({ message: 'Token no proporcionado' });
    }
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.log('Token no válido');
            return res.status(403).json({ message: 'Token no válido' });
        }
        req.user = user;
        next();
    });
};

app.get('/usuarios', authMiddleware, async (req, res) => {
    console.log(`Solicitud para obtener usuario con email ${req.user.email}`);
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [req.user.email]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: 'Error del servidor' });
    }
});

app.listen(3000, () => {
    console.log('Servidor corriendo en el puerto 3000');
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Ocurrió un error en el servidor' });
});
