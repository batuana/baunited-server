const mongoose = require('mongoose');
const dotenv = require('dotenv');
const socketio = require('socket.io');

process.on('uncaughtException', err => {
  console.log('UNCAUGHT EXCEPTION! 🔴 Shutting down...');
  console.log(err.name, err.message);
  process.exit(1); // must
});

dotenv.config({ path: './config.env' });
const app = require('./app');

const DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);

mongoose.connect(DB).then(con => {
  console.log('DB connection successful');
});

const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`App running on port ${port}...`);
});

const io = socketio(server);

io.of('/').on('connection', socket => {
  console.log(`${socket.id} has connected.`);
  socket.on('messageToServer', message => {
    console.log(`Incoming message: ${message}`);
    io.emit('messageFromServer', {
      message,
      receiver: 'me',
      sender: 'you',
      createdAt: '18:31',
    });
  });
});

// last safety net
process.on('unhandledRejection', err => {
  console.log('UNHANDLED REJECTION! 🔴 Shutting down...');
  console.log(err.name, err.message);
  // NOTE we give the server time to finish all the requests that are still pending or being handled at the time, then the server is killed
  server.close(() => {
    process.exit(1); // optional
  });
});
