// Arquivo: server.js (Versão 3 - Conectado ao MongoDB)

// --- 1. IMPORTAÇÕES ---
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose'); // Importa o Mongoose
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// --- 2. CONFIGURAÇÕES (MIDDLEWARES) ---
app.use(cors());
app.use(express.json());

// --- 3. CONEXÃO COM O BANCO DE DADOS MONGODB ATLAS ---
// Substitua pela SUA string de conexão que você copiou do site do Atlas!
const MONGO_URI = 'mongodb+srv://andersonteixeira4:O6IGNPgnW8UjOz4g@cluster0.wxxpmnu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGO_URI)
  .then(() => console.log('Conexão com o MongoDB Atlas bem-sucedida!'))
  .catch(err => console.error('Erro ao conectar com o MongoDB:', err));

// --- 4. DEFINIÇÃO DO SCHEMA E MODEL ---
// O "Schema" é a planta baixa, a estrutura de como um "concurso" deve ser.
const concursoSchema = new mongoose.Schema({
    instituicao: String,
    vagas: String,
    escolaridade: [String],
    salario: String,
    prazo: String, // Mantendo como string YYYY-MM-DD
    estado: String,
    cargos: String,
     resumo: String,      
    linkEdital: String,
    ambito: { // <-- NOVO CAMPO
        type: String,
        enum: ['Nacional', 'Estadual', 'Municipal'], // Só permite esses valores
        default: 'Municipal', // 
         required: true
    },
     estado: { // <-- CAMPO MODIFICADO
        type: String
        
    }
    // Mongoose automaticamente adiciona um campo _id único para nós.
});


// O "Model" é a ferramenta que usa o Schema para interagir com a coleção no banco de dados.
// É como o "gerente" da coleção 'Concursos'.
const Concurso = mongoose.model('Concurso', concursoSchema);

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true }, // O email deve ser único
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// No arquivo server.js

// --- MIDDLEWARE DE VERIFICAÇÃO DE TOKEN ---
function verifyToken(req, res, next) {
    // Pega o token do cabeçalho da requisição (header)
    const bearerHeader = req.headers['authorization'];

    if (typeof bearerHeader !== 'undefined') {
        // O cabeçalho vem no formato "Bearer <token>". Precisamos separar o token.
        const bearerToken = bearerHeader.split(' ')[1];
        req.token = bearerToken;

        // Verifica se o token é válido
        jwt.verify(req.token, 'seu_segredo_super_secreto', (err, authData) => {
            if (err) {
                res.sendStatus(403); // Proibido (Forbidden)
            } else {
                req.authData = authData; // Salva os dados do usuário (id, email) na requisição
                next(); // O token é válido, pode prosseguir para a rota
            }
        });
    } else {
        res.sendStatus(401); // Não autorizado (Unauthorized)
    }
}

// --- 5. ROTAS DA API (AGORA USANDO O BANCO DE DADOS) ---

// Rota para BUSCAR todos os concursos do banco de dados
// Rota para BUSCAR todos os concursos (com filtros, busca e ordenação)
app.get('/api/concursos', async (req, res) => {
    try {
        const { search, estado } = req.query;
        const filtro = {};

        if (search) {
            filtro.instituicao = { $regex: search, $options: 'i' };
        }

        if (estado && estado !== 'todos') {
            // Se um estado for selecionado, mostramos apenas concursos daquele estado.
            // Concursos nacionais (que não têm estado) são naturalmente excluídos.
            filtro.estado = estado;
            filtro.ambito = { $ne: 'Nacional' }; // Garante que não mostremos nacionais no filtro de estado
        }

        // A ordenação continua a mesma, pois o front-end fará o agrupamento visual
        const ordenacao = { instituicao: 1 };

        const concursos = await Concurso.find(filtro).sort(ordenacao);

        res.json(concursos);
    } catch (error) {
        res.status(500).json({ message: 'Erro ao buscar concursos', error: error });
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
        res.status(500).json({ message: 'Erro ao buscar concurso', error: error });
    }
});

// Rota para CRIAR um novo concurso no banco de dados

app.post('/api/concursos', verifyToken, async (req, res) => {
    try {
        const dadosNovoConcurso = req.body;

        // NOSSA VALIDAÇÃO MANUAL
        if (dadosNovoConcurso.ambito !== 'Nacional' && (!dadosNovoConcurso.estado || dadosNovoConcurso.estado.trim() === '')) {
            return res.status(400).json({ message: 'A sigla do estado é obrigatória para concursos de âmbito Estadual ou Municipal.' });
        }

        // Se for Nacional, garante que não tenha estado
        if (dadosNovoConcurso.ambito === 'Nacional') {
            dadosNovoConcurso.estado = undefined;
        }

        const novoConcurso = new Concurso(dadosNovoConcurso);
        await novoConcurso.save();

        console.log('Novo concurso salvo no banco de dados:', novoConcurso);
        res.status(201).json({ message: 'Concurso criado com sucesso!', data: novoConcurso });

    } catch (error) {
        res.status(400).json({ message: 'Erro ao criar concurso', error: error.message });
    }
});

// Rota para DELETAR um concurso específico pelo seu ID
app.delete('/api/concursos/:id', verifyToken, async (req, res) => {
    try {
        // 1. Pega o ID que vem nos parâmetros da URL (ex: /api/concursos/12345)
        const concursoId = req.params.id;

        // 2. Usa o Mongoose para encontrar o documento por esse ID e deletá-lo
        const concursoDeletado = await Concurso.findByIdAndDelete(concursoId);

        if (!concursoDeletado) {
            // Se não encontrou um concurso com esse ID, retorna um erro 404
            return res.status(404).json({ message: 'Concurso não encontrado.' });
        }

        console.log('Concurso deletado:', concursoId);
        res.json({ message: 'Concurso deletado com sucesso!' });

    } catch (error) {
        res.status(500).json({ message: 'Erro ao deletar concurso', error: error });
    }
});

// No arquivo server.js

// Rota para ATUALIZAR (EDITAR) um concurso existente pelo ID
// No server.js
app.put('/api/concursos/:id', verifyToken, async (req, res) => {
    try {
        const concursoParaAtualizar = await Concurso.findById(req.params.id);
        if (!concursoParaAtualizar) {
            return res.status(404).json({ message: 'Concurso não encontrado.' });
        }

        // Atualiza os dados em memória
        Object.assign(concursoParaAtualizar, req.body);

        // NOSSA VALIDAÇÃO MANUAL
        if (concursoParaAtualizar.ambito !== 'Nacional' && (!concursoParaAtualizar.estado || concursoParaAtualizar.estado.trim() === '')) {
            // Se NÃO for Nacional e o estado estiver vazio, retorna um erro.
            return res.status(400).json({ message: 'A sigla do estado é obrigatória para concursos de âmbito Estadual ou Municipal.' });
        }

        // Se for Nacional, garantimos que o campo estado seja removido
        if (concursoParaAtualizar.ambito === 'Nacional') {
            concursoParaAtualizar.estado = undefined;
        }

        const concursoSalvo = await concursoParaAtualizar.save();
        res.json({ message: 'Concurso atualizado com sucesso!', data: concursoSalvo });

    } catch (error) {
        res.status(500).json({ message: 'Erro ao atualizar concurso', error: error.message });
    }
});
// Rota para REGISTRAR um novo usuário (administrador)
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Verifica se o usuário já existe
        const usuarioExistente = await User.findOne({ email: email });
        if (usuarioExistente) {
            return res.status(400).json({ message: 'Este e-mail já está em uso.' });
        }

        // 2. Criptografa a senha
        const salt = await bcrypt.genSalt(10); // Gera o "tempero" para o hash
        const hashedPassword = await bcrypt.hash(password, salt); // Cria o hash da senha

        // 3. Cria o novo usuário com a senha criptografada
        const novoUsuario = new User({
            email: email,
            password: hashedPassword
        });

        // 4. Salva o usuário no banco de dados
        await novoUsuario.save();

        console.log('Novo administrador registrado:', novoUsuario.email);
        res.status(201).json({ message: 'Administrador registrado com sucesso!' });

    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});
// No arquivo server.js, dentro da seção de ROTAS DA API

// Rota para LOGIN de um usuário
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Procura o usuário pelo email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Credenciais inválidas.' }); // Mensagem genérica por segurança
        }

        // 2. Compara a senha enviada com a senha criptografada no banco de dados
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Credenciais inválidas.' });
        }

        // 3. Se a senha está correta, cria o Token (a "chave de acesso")
        const token = jwt.sign(
            { id: user._id, email: user.email }, // Informações que queremos guardar no token
            'seu_segredo_super_secreto',           // Uma "chave secreta" para assinar o token. Mude isso para algo seu!
            { expiresIn: '1h' }                    // O token expira em 1 hora
        );

        console.log('Login bem-sucedido para:', user.email);
        res.json({ message: 'Login bem-sucedido!', token: token });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// ... (o resto do seu código, como o app.listen, continua igual)

// --- 6. INICIAR O SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor da API rodando na porta ${PORT}.`);
});