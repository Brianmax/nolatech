const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { expressjwt: jwtMiddleware } = require('express-jwt');

const app = express();
const port = 3000;

const SECRET_KEY = 'tu_secreto';  // Cambia esto por una clave secreta segura

mongoose.connect('mongodb+srv://user:jUanFQIc3VJOs0z3@cluster0.civkdh0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Error de conexión:'));
db.once('open', () => {
    console.log('Conectado a la base de datos');
});

// Middleware
app.use(bodyParser.json());

// Definir un esquema y un modelo de Mongoose
const Schema = mongoose.Schema;
const UserSchema = new Schema({
    nombre: {
        type: String,
        required: true
    },
    apellido: {
        type: String,
        required: true
    },
    usuario: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
});

const User = mongoose.model('User', UserSchema);

app.get('/', (req, res) => {
    res.send('Hola Mundo!');
});

// Obtener todos los usuarios (protegido)
app.get('/api/v1/users', jwtMiddleware({ secret: SECRET_KEY, algorithms: ['HS256'] }), async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (err) {
        res.status(500).send(err);
    }
});

// Crear un nuevo usuario
app.post('/users', async (req, res) => {
    const user = new User(req.body);
    const usuario = await User.exists({ usuario: user.usuario });
    const email = await User.exists({ email: user.email });
    if (usuario || email) {
        res.status(400).send('El usuario ya existe');
        return;
    }
    const errors = validateUserData(user);
    if (errors) {
        res.status(400).json({ errors });
        return;
    }
    try {
        user.password = await bcrypt.hash(user.password, 10);
        const userCreated = await user.save();
        const token = jwt.sign({ id: userCreated._id }, SECRET_KEY, { expiresIn: '1h' });
        res.status(201).send({ user: userCreated, token });
    } catch (err) {
        res.status(500).send(err);
    }
});

// Login de usuario
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ error: 'Usuario o contraseña incorrectos' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ error: 'Usuario o contraseña incorrectos' });
        }

        const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '1h' });

        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

app.put('/api/v1/users/:id', jwtMiddleware({ secret: SECRET_KEY, algorithms: ['HS256'] }), async (req, res) => {
    const { id } = req.params;
    const user = req.body;
    const existingUser = await User.findById(id);
    if (!existingUser) {
        res.status(404).send('El usuario no existe');
        return;
    }
    const errors = validateUserData(user);
    if (errors) {
        res.status(400).json({ errors });
        return;
    }
    try {
        const updatedUser = await User.findByIdAndUpdate(id, user, { new: true });
        res.json(updatedUser);
    } catch (err) {
        res.status(500).send(err);
    }
});

const validateUserData = (data) => {
    const errors = [];
    if (!data.nombre || typeof data.nombre !== 'string' || !validateNombre(data.nombre)) {
        errors.push('El nombre es requerido y debe ser una cadena de texto.');
    }
    if (!data.apellido || typeof data.apellido !== 'string' || !validateApellido(data.apellido)) {
        errors.push('El apellido es requerido y debe ser una cadena de texto.');
    }
    if (!data.usuario || typeof data.usuario !== 'string' || !validateNombre(data.usuario)) {
        errors.push('El usuario es requerido y debe ser una cadena de texto.');
    }
    if (!data.email || typeof data.email !== 'string' || !validateEmail(data.email)) {
        errors.push('El email es requerido, debe ser una cadena de texto y debe tener un formato válido.');
    }
    if (!data.password || typeof data.password !== 'string' || !validatePassword(data.password)) {
        errors.push('La contraseña es requerida, debe ser una cadena de texto y debe cumplir con los requisitos de seguridad.');
    }
    return errors.length > 0 ? errors : null;
}

const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

const validatePassword = (password) => {
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,40}$/;
    return passwordRegex.test(password);
}

const validateNombre = (nombre) => {
    const nombreRegex = /^[a-zA-Z]+$/;
    return nombreRegex.test(nombre);
}

const validateApellido = (apellido) => {
    const apellidoRegex = /^[a-zA-Z]+$/;
    return apellidoRegex.test(apellido);
}

// Iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor escuchando en http://localhost:${port}`);
});