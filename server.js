
const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

let historicoMensagens = [];
const LIMITE_MENSAGENS = 50;
const participantesOnline = new Map();

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

function textoSeguro(valor, padrao = '') {
    return typeof valor === 'string'
        ? valor.trim().slice(0, 200)
        : padrao;
}

function fotoSegura(valor) {
    if (typeof valor !== 'string' || !valor.trim()) return '';

    try {
        const url = new URL(valor.trim());
        return ['http:', 'https:'].includes(url.protocol)
            ? url.href
            : '';
    } catch {
        return '';
    }
}

function enviarListaOnline() {
    io.emit(
        'lista_participantes',
        Array.from(participantesOnline.entries()).map(([id, pessoa]) => ({
            id,
            personagem: pessoa.personagem,
            foto: pessoa.foto
        }))
    );
}

function registrarParticipante(socket, dados = {}) {
    const anterior = participantesOnline.get(socket.id) || {};

    participantesOnline.set(socket.id, {
        personagem:
            textoSeguro(dados.personagem, anterior.personagem || 'Anonymous Wanderer')
            || 'Anonymous Wanderer',
        foto: fotoSegura(dados.foto) || anterior.foto || ''
    });

    enviarListaOnline();
}

io.on('connection', (socket) => {
    console.log('Connected:', socket.id);

    socket.emit('carregar_historico', historicoMensagens);
    socket.emit(
        'lista_participantes',
        Array.from(participantesOnline.entries()).map(([id, pessoa]) => ({
            id,
            personagem: pessoa.personagem,
            foto: pessoa.foto
        }))
    );

    socket.on('registrar_participante', (dados) => {
        registrarParticipante(socket, dados);
    });

    socket.on('msg_rp', (dados = {}) => {
        const personagem =
            textoSeguro(dados.personagem, 'Anonymous Wanderer')
            || 'Anonymous Wanderer';

        const texto = typeof dados.texto === 'string'
            ? dados.texto.slice(0, 4000)
            : '';

        if (!texto.trim()) return;

        const foto = fotoSegura(dados.foto);

        registrarParticipante(socket, { personagem, foto });

        const mensagem = {
            id: socket.id,
            personagem,
            texto,
            foto
        };

        historicoMensagens.push(mensagem);

        if (historicoMensagens.length > LIMITE_MENSAGENS) {
            historicoMensagens.shift();
        }

        io.emit('enviar_msg_rp', mensagem);
    });

    socket.on('disconnect', () => {
        participantesOnline.delete(socket.id);
        io.emit('participante_saiu', socket.id);
        enviarListaOnline();

        console.log('Disconnected:', socket.id);
    });
});

const PORT = process.env.PORT || 3000;

http.listen(PORT, () => {
    console.log('LobbyZero server running on port ' + PORT);
});
