require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
// * 
app.use(cors());
app.use(express.json());
const MONGO_URI = process.env.MONGO_URI;
mongoose.connect(MONGO_URI)
  .then(() => console.log('Conexão com o MongoDB Atlas bem-sucedida!'))
  .catch(err => console.error('Erro ao conectar com o MongoDB:', err));
const concursoSchema = new mongoose.Schema({
    instituicao: String,
    vagas: String,
    escolaridade: [String],
    salario: String,
    prazo: String, 
    estado: String,
    cargos: String,
     resumo: String,      
    linkEdital: String,
    ambito: { 
        type: String,
        enum: ['Nacional', 'Estadual', 'Municipal'], 
        default: 'Municipal', 
         required: true
    },
     estado: { 
        type: String
        
    }
    
});

const Concurso = mongoose.model('Concurso', concursoSchema);

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true }, 
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

function verifyToken(req, res, next) {
   
    const bearerHeader = req.headers['authorization'];

    if (typeof bearerHeader !== 'undefined') {
        const bearerToken = bearerHeader.split(' ')[1];
        req.token = bearerToken;
        jwt.verify(req.token, process.env.JWT_SECRET, (err, authData) => {
            if (err) {
                res.sendStatus(403); 
            } else {
                req.authData = authData; 
                next(); 
            }
        });
    } else {
        res.sendStatus(401);
    }
}

app.get('/api/concursos', async (req, res) => {
    try {
        const { search, estado } = req.query;
        const filtro = {};

        if (search) {
            filtro.instituicao = { $regex: search, $options: 'i' };
        }

        if (estado && estado !== 'todos') {
            filtro.estado = estado;
            filtro.ambito = { $ne: 'Nacional' }; 
        }

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

app.post('/api/concursos', verifyToken, async (req, res) => {
    try {
        const dadosNovoConcurso = req.body;        
        if (dadosNovoConcurso.ambito !== 'Nacional' && (!dadosNovoConcurso.estado || dadosNovoConcurso.estado.trim() === '')) {
            return res.status(400).json({ message: 'A sigla do estado é obrigatória para concursos de âmbito Estadual ou Municipal.' });
        }

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

app.delete('/api/concursos/:id', verifyToken, async (req, res) => {
    try {
        const concursoId = req.params.id;

        const concursoDeletado = await Concurso.findByIdAndDelete(concursoId);

        if (!concursoDeletado) {
            return res.status(404).json({ message: 'Concurso não encontrado.' });
        }

        console.log('Concurso deletado:', concursoId);
        res.json({ message: 'Concurso deletado com sucesso!' });

    } catch (error) {
        res.status(500).json({ message: 'Erro ao deletar concurso', error: error });
    }
});

app.put('/api/concursos/:id', verifyToken, async (req, res) => {
    try {
        const concursoParaAtualizar = await Concurso.findById(req.params.id);
        if (!concursoParaAtualizar) {
            return res.status(404).json({ message: 'Concurso não encontrado.' });
        }

        Object.assign(concursoParaAtualizar, req.body);

        if (concursoParaAtualizar.ambito !== 'Nacional' && (!concursoParaAtualizar.estado || concursoParaAtualizar.estado.trim() === '')) {
            return res.status(400).json({ message: 'A sigla do estado é obrigatória para concursos de âmbito Estadual ou Municipal.' });
        }

        if (concursoParaAtualizar.ambito === 'Nacional') {
            concursoParaAtualizar.estado = undefined;
        }

        const concursoSalvo = await concursoParaAtualizar.save();
        res.json({ message: 'Concurso atualizado com sucesso!', data: concursoSalvo });

    } catch (error) {
        res.status(500).json({ message: 'Erro ao atualizar concurso', error: error.message });
    }
});

app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;        
        const usuarioExistente = await User.findOne({ email: email });
        if (usuarioExistente) {
            return res.status(400).json({ message: 'Este e-mail já está em uso.' });
        }        
        const salt = await bcrypt.genSalt(10); 
        const hashedPassword = await bcrypt.hash(password, salt);         
        const novoUsuario = new User({
            email: email,
            password: hashedPassword
        });
        
        await novoUsuario.save();

        console.log('Novo administrador registrado:', novoUsuario.email);
        res.status(201).json({ message: 'Administrador registrado com sucesso!' });

    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;        
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Credenciais inválidas.' }); 
        }        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Credenciais inválidas.' });
        }        
        const token = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        console.log('Login bem-sucedido para:', user.email);
        res.json({ message: 'Login bem-sucedido!', token: token });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.listen(PORT, () => {
  console.log(`Servidor da API rodando na porta ${PORT}.`);
});