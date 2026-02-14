import express from 'express';
import { createUser, getAllUsers } from './userService.js';

const app = express();
const PORT = 3000;

app.use(express.json());

app.get('/users', async (req, res) => {
  const users = await getAllUsers();
  res.json(users);
});

app.post('/users', async (req, res) => {
  const { email } = req.body;
  const user = await createUser(email);
  res.status(201).json(user);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;
