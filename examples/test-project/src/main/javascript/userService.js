const users = [];

export async function createUser(email) {
  const user = {
    id: users.length + 1,
    email,
    createdAt: new Date(),
  };
  users.push(user);
  return user;
}

export async function getAllUsers() {
  return [...users];
}

export async function getUserById(id) {
  return users.find(u => u.id === id);
}

export class UserRepository {
  constructor() {
    this.cache = new Map();
  }

  async findAll() {
    return getAllUsers();
  }

  async findById(id) {
    if (this.cache.has(id)) {
      return this.cache.get(id);
    }
    const user = await getUserById(id);
    if (user) {
      this.cache.set(id, user);
    }
    return user;
  }
}
