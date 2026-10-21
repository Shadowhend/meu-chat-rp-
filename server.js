const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

io.on('connection', (socket) => {
    socket.on('msg_rp', (dados) => {
        // Envia o personagem, texto, foto e o id único de quem mandou
        io.emit('enviar_msg_rp', {
            id: socket.id,
            personagem: dados.personagem,
            texto: dados.texto,
            foto: dados.foto
        });
    });
});

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => {
    console.log("Servidor rodando na porta " + PORT);
});
