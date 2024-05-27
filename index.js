const express = require('express');
const http = require('http');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static('public'));

// Register user
app.post('/register', async (req, res) => {
  const { email, password, username } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, username },
    });
    res.json(user);
  } catch (error) {
    res.status(400).send('User already exists');
  }
});

// Login user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });

  if (user && await bcrypt.compare(password, user.password)) {
    res.json({ userId: user.id });
  } else {
    res.status(401).send('Invalid credentials');
  }
});

// Get all users
app.get('/users', async (req, res) => {
  const users = await prisma.user.findMany();
  res.json(users);
});

// Get user by id
app.get('/users/:id', async (req, res) => {
  const { id } = req.params;
  const user = await prisma.user.findUnique({ where: { id: parseInt(id) } });
  res.json(user);
});

io.on('connection', (socket) => {
  console.log('a user connected');

  socket.on('message', async ({ senderId, receiverId, content }) => {
    try {
      const message = await prisma.message.create({
        data: {
          content,
          senderId:parseInt(senderId),
          receiverId:parseInt(receiverId),
        },
      });

      io.emit('message', message);
    } catch (err) {
      console.error('Error saving message:', err);
    }
  });

  socket.on('disconnect', () => {
    console.log('user disconnected');
  });
});

server.listen(3000, () => {
  console.log('listening on *:3000');
});
