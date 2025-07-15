require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

const corsOptions = {
  origin: [
    'http://localhost:5173', 
    'http://localhost:5174', 
    'https://www.econcursou.com.br',
    'https://econcursou.com.br', 
    'https://melodic-hotteok-ce17e6.netlify.app'
  ],
  optionsSuccessStatus: 200
};
app.options('*', cors(corsOptions));
app.use(cors(corsOptions));

// Middleware para interpretar o corpo das requisições como JSON
app.use(express.json());


// --- 3. CONEXÃO COM O BANCO DE DADOS MONGODB ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Conexão com o MongoDB Atlas bem-sucedida!'))
  .catch(err => console.error('Erro ao conectar com o MongoDB:', err));


// --- 4. DEFINIÇÃO DOS SCHEMAS E MODELS ---

// Schema para os links (subdocumento)
const LinkSchema = new mongoose.Schema({
    nome: { type: String, required: true },
    url: { type: String, required: true }
});

// Schema principal para os Concursos
const concursoSchema = new mongoose.Schema({
    instituicao: { type: String, required: true },
    vagas: String,
    escolaridade: [String],
    salario: String,
    prazo: String,
    estado: String,
    resumo: String,
    cargos: String,
    ambito: {
        type: String,
        enum: ['Nacional', 'Estadual', 'Municipal'],
        required: true
    },
    links: [LinkSchema]
});

// Schema para os Usuários (administradores)
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

// Criação dos Models
const Concurso = mongoose.model('Concurso', concursoSchema);
const User = mongoose.model('User', UserSchema);


// --- 5. MIDDLEWARE DE VERIFICAÇÃO DE TOKEN (O "GUARDA") ---
function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader === 'undefined') {
        return res.status(401).json({ message: 'Acesso não autorizado. Token não fornecido.' });
    }
    const bearerToken = bearerHeader.split(' ')[1];
    jwt.verify(bearerToken, process.env.JWT_SECRET, (err, authData) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido ou expirado.' });
        }
        req.authData = authData;
        next();
    });
}


// --- 6. ROTAS DA API ---

// Rota de teste
app.get('/', (req, res) => {
    res.send('API do eConcursou no ar!');
});

// -- ROTAS PÚBLICAS --
app.get('/api/concursos', async (req, res) => {
    try {
        const { search, estado } = req.query;
        const filtro = {};
        if (search) {
            filtro.instituicao = { $regex: search, $options: 'i' };
        }
        if (estado && estado !== 'todos') {
            filtro.ambito = { $ne: 'Nacional' };
            filtro.estado = estado;
        }
        const ordenacao = { instituicao: 1 };
        const concursos = await Concurso.find(filtro).sort(ordenacao);
        res.json(concursos);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar concursos', error });
    }
});

app.get('/api/concursos/:id', async (req, res) => {
    try {
        const concurso = await Concurso.findById(req.params.id);
        if (!concurso) {
            return res.status(404).json({ message: 'Concurso não encontrado.' });
        }
        res.json(concurso);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar concurso', error });
    }
});

// -- ROTAS DE AUTENTICAÇÃO --
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
        const usuarioExistente = await User.findOne({ email });
        if (usuarioExistente) return res.status(400).json({ message: 'Este e-mail já está em uso.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const novoUsuario = new User({ email, password: hashedPassword });
        await novoUsuario.save();
        res.status(201).json({ message: 'Administrador registrado com sucesso!' });
    } catch (error) {
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Credenciais inválidas.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Credenciais inválidas.' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login bem-sucedido!', token });
    } catch (error) {
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// -- ROTAS PROTEGIDAS DE GERENCIAMENTO --
app.post('/api/concursos', verifyToken, async (req, res) => {
    try {
        const novoConcurso = new Concurso(req.body);
        await novoConcurso.save();
        res.status(201).json({ message: 'Concurso criado com sucesso!', data: novoConcurso });
    } catch (error) {
        res.status(400).json({ message: 'Erro ao criar concurso', error: error.message });
    }
});

app.put('/api/concursos/:id', verifyToken, async (req, res) => {
    try {
        const concurso = await Concurso.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!concurso) return res.status(404).json({ message: 'Concurso não encontrado' });
        res.json({ message: 'Concurso atualizado com sucesso!', data: concurso });
    } catch (error) {
        res.status(400).json({ message: 'Erro ao atualizar concurso', error: error.message });
    }
});

app.delete('/api/concursos/:id', verifyToken, async (req, res) => {
    try {
        const concurso = await Concurso.findByIdAndDelete(req.params.id);
        if (!concurso) return res.status(404).json({ message: 'Concurso não encontrado' });
        res.json({ message: 'Concurso deletado com sucesso!' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao deletar concurso', error });
    }
});


// --- 7. INICIAR O SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor da API rodando na porta ${PORT}.`);
});