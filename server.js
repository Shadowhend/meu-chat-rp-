const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

// Aqui fica salva a memória das últimas mensagens do chat
let historicoMensagens = [];
const LIMITE_MENSAGENS = 50;

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

io.on('connection', (socket) => {
    // ASSIM QUE ALGUÉM ENTRA OU DÁ F5: Envia todo o histórico guardado só para essa pessoa
    socket.emit('carregar_historico', historicoMensagens);

    socket.on('msg_rp', (dados) => {
        const novaMensagem = {
            id: socket.id, // ID de quem enviou originalmente
            personagem: dados.personagem,
            texto: dados.texto,
            foto: dados.foto
        };

        // Salva a mensagem na lista do histórico
        historicoMensagens.push(novaMensagem);

        // Se passar do limite, remove a mensagem mais antiga para o servidor não travar
        if (historicoMensagens.length > LIMITE_MENSAGENS) {
            historicoMensagens.shift();
        }

        // Transmite a nova mensagem para todo mundo em tempo real
        io.emit('enviar_msg_rp', novaMensagem);
    });
});

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => {
    console.log("Servidor rodando na porta " + PORT);
});
