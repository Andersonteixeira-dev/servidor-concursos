require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const slugify = require('slugify');
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

app.use(cors(corsOptions));
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Conexão com o MongoDB Atlas bem-sucedida!'))
    .catch(err => console.error('Erro ao conectar com o MongoDB:', err));

const LinkSchema = new mongoose.Schema({
    nome: { type: String, required: true },
    url: { type: String, required: true }
});

const concursoSchema = new mongoose.Schema({
    instituicao: { type: String, required: true },
    vagas: String,
    escolaridade: [String],
    salario: String,
    dataInicioInscricao: { type: String },
    dataFimInscricao: { type: String },
    textoInscricao: String,
    estado: String,
    resumo: String,
    cargos: String,
    ambito: {
        type: String,
        enum: ['Nacional', 'Estadual', 'Municipal'],
        required: true
    },
    links: [LinkSchema],
    slug: { type: String, required: true, unique: true, index: true }
});

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const postSchema = new mongoose.Schema({
    titulo: { type: String, required: true },
    resumo: { type: String, required: true },
    conteudo: { type: String, required: true },
    imagemCapa: { type: String }, // URL para a imagem de destaque
    slug: { type: String, required: true, unique: true, index: true },
    dataPublicacao: { type: Date, default: Date.now }
});

postSchema.pre('save', async function(next) {
    if (this.isModified('titulo') || this.isNew) {
        const baseSlug = slugify(this.titulo, { lower: true, strict: true });
        let finalSlug = baseSlug;
        let count = 1;
        // Garante que o slug seja único
        while (await mongoose.models.Post.findOne({ slug: finalSlug })) {
            finalSlug = `${baseSlug}-${count}`;
            count++;
        }
        this.slug = finalSlug;
    }
    next();
});

const Concurso = mongoose.model('Concurso', concursoSchema);
const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', postSchema);

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

app.get('/', (req, res) => {
    res.send('API do eConcursou no ar!');
});

app.get('/api/concursos/slug/:slug', async (req, res) => {
    try {        
        const concurso = await Concurso.findOne({ slug: req.params.slug });
        if (!concurso) {
            return res.status(404).json({ message: 'Concurso não encontrado.' });
        }
        res.json(concurso);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar concurso', error });
    }
});

app.get('/api/concursos', async (req, res) => {
    try {
        const { search, estado } = req.query;
        const filtro = {};
        if (estado && estado !== 'todos') {
            filtro.ambito = { $ne: 'Nacional' };
            filtro.estado = estado;
        }
        if (search) {
            const regex = { $regex: search, $options: 'i' };
            filtro.$or = [
                { instituicao: regex },
                { cargos: regex },
                { escolaridade: regex }
            ];
        }

        const concursos = await Concurso.find(filtro).sort({ instituicao: 1 });

        const dataAtual = new Date();
        concursos.forEach(concurso => {
            const inicio = new Date(concurso.dataInicioInscricao);
            if (dataAtual < inicio) {
                concurso.statusInscricao = 'Previsto';
            } else if (dataAtual > new Date(concurso.dataFimInscricao)) {
                concurso.statusInscricao = 'Encerrado';
            } else {
                concurso.statusInscricao = 'Aberto';
            }
        });

        res.json(concursos);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar concursos', error: error.message });
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

// --- ROTAS PARA NOTÍCIAS ---
app.get('/api/noticias', async (req, res) => {
    try {
        const posts = await Post.find().sort({ dataPublicacao: -1 });
        res.json(posts);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar notícias', error });
    }
});

app.get('/api/noticias/slug/:slug', async (req, res) => {
    try {
        const post = await Post.findOne({ slug: req.params.slug });
        if (!post) return res.status(404).json({ message: 'Notícia não encontrada.' });
        res.json(post);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar notícia', error });
    }
});

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

app.post('/api/concursos', verifyToken, async (req, res) => {
     try {
        const dados = req.body;

        // 1. Gera o slug a partir da instituição
        let baseSlug = slugify(dados.instituicao, { lower: true, strict: true });
        let finalSlug = baseSlug;
        let count = 1;
        
        while (await Concurso.findOne({ slug: finalSlug })) {
            finalSlug = `${baseSlug}-${count}`;
            count++;
        }
        
        const dadosComSlug = { ...dados, slug: finalSlug };

        const novoConcurso = new Concurso(dadosComSlug);
        await novoConcurso.save();
        res.status(201).json({ message: 'Concurso criado com sucesso!', data: novoConcurso });
    } catch (error) {
        res.status(400).json({ message: 'Erro ao criar concurso', error: error.message });
    }
});

app.put('/api/concursos/:id', verifyToken, async (req, res) => {
     try {
        const dadosAtualizados = req.body;
        
        if (dadosAtualizados.instituicao) {
            let baseSlug = slugify(dadosAtualizados.instituicao, { lower: true, strict: true });           
            dadosAtualizados.slug = baseSlug;
        }

        const concurso = await Concurso.findByIdAndUpdate(req.params.id, dadosAtualizados, { new: true, runValidators: true });
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

app.post('/api/noticias', verifyToken, async (req, res) => {
    try {
        const novoPost = new Post(req.body);
        await novoPost.save();
        res.status(201).json({ message: 'Notícia criada com sucesso!', data: novoPost });
    } catch (error) {
        res.status(400).json({ message: 'Erro ao criar notícia', error: error.message });
    }
});

app.put('/api/noticias/:id', verifyToken, async (req, res) => {
    try {
        const post = await Post.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!post) return res.status(404).json({ message: 'Notícia não encontrada' });
        res.json({ message: 'Notícia atualizada com sucesso!', data: post });
    } catch (error) {
        res.status(400).json({ message: 'Erro ao atualizar notícia', error: error.message });
    }
});

app.delete('/api/noticias/:id', verifyToken, async (req, res) => {
    try {
        const post = await Post.findByIdAndDelete(req.params.id);
        if (!post) return res.status(404).json({ message: 'Notícia não encontrada' });
        res.json({ message: 'Notícia deletada com sucesso!' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao deletar notícia', error });
    }
});

app.listen(PORT, () => {
  console.log(`Servidor da API rodando na porta ${PORT}.`);
});
