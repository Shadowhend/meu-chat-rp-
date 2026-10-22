const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

// Keep the most recent messages in memory.
let historicoMensagens = [];
const LIMITE_MENSAGENS = 50;

// Only currently connected sockets are stored here.
const participantesOnline = new Map();

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

function textoSeguro(value, fallback = '') {
    return typeof value === 'string' ? value.trim().slice(0, 200) : fallback;
}

function fotoSegura(value) {
    if (typeof value !== 'string' || !value.trim()) return '';
    try {
        const url = new URL(value.trim());
        return (url.protocol === 'https:' || url.protocol === 'http:') ? url.href : '';
    } catch (_) {
        return '';
    }
}

function listaPublicaParticipantes() {
    return Array.from(participantesOnline.entries()).map(([id, pessoa]) => ({
        id,
        personagem: pessoa.personagem,
        foto: pessoa.foto
    }));
}

function transmitirParticipantes() {
    io.emit('lista_participantes', listaPublicaParticipantes());
}

function registrarParticipante(socket, dados = {}) {
    const anterior = participantesOnline.get(socket.id) || {};
    participantesOnline.set(socket.id, {
        personagem: textoSeguro(dados.personagem, anterior.personagem || 'Anonymous Wanderer') || 'Anonymous Wanderer',
        foto: fotoSegura(dados.foto) || anterior.foto || ''
    });
    transmitirParticipantes();
}

io.on('connection', (socket) => {
    // Preserve the existing history event.
    socket.emit('carregar_historico', historicoMensagens);

    // Send the current online list to this client.
    socket.emit('lista_participantes', listaPublicaParticipantes());

    // The browser sends the character name/avatar when connecting or editing them.
    socket.on('registrar_participante', (dados) => {
        registrarParticipante(socket, dados);
    });

    socket.on('msg_rp', (dados = {}, callback) => {
        const personagem = textoSeguro(dados.personagem, 'Anonymous Wanderer') || 'Anonymous Wanderer';
        const foto = fotoSegura(dados.foto);

        // A message also refreshes the sender's displayed identity.
        registrarParticipante(socket, { personagem, foto });

        const novaMensagem = {
            id: socket.id,
            personagem,
            texto: typeof dados.texto === 'string' ? dados.texto.slice(0, 4000) : '',
            foto: foto || ''
        };

        if (!novaMensagem.texto) {
            if (typeof callback === 'function') callback({ error: 'Message cannot be empty.' });
            return;
        }

        historicoMensagens.push(novaMensagem);
        if (historicoMensagens.length > LIMITE_MENSAGENS) {
            historicoMensagens.shift();
        }

        // Preserve the event used by the existing HTML.
        io.emit('enviar_msg_rp', novaMensagem);
        if (typeof callback === 'function') callback({ ok: true });
    });

    socket.on('disconnect', () => {
        participantesOnline.delete(socket.id);
        // Let all connected browsers immediately remove this participant.
        io.emit('participante_saiu', socket.id);
        transmitirParticipantes();
    });
});

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => {
    console.log('Server running on port ' + PORT);
});
