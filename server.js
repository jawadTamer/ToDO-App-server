const cors = require("cors");
const express = require("express");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 8000;
const SECRET_KEY = process.env.SECRET_KEY || "fallback_secret";

app.use(express.json());
app.use(cors());

// Utility functions
const readData = (file) => {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify([]));
    return [];
  }
  const data = fs.readFileSync(file, "utf8");
  return data ? JSON.parse(data) : [];
};

const writeData = (file, data) => {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
};

// Validation middleware
const validateRegistration = (req, res, next) => {
  const { name, email, password, phone, age, address } = req.body;
  let errors = {};
  if (!name) errors.name = "Name is required";
  if (!email) errors.email = "Email is required";
  if (!password) errors.password = "Password is required";
  if (!phone) errors.phone = "Phone number is required";
  if (!age) errors.age = "Age is required";
  if (!address) errors.address = "Address is required";

  if (Object.keys(errors).length > 0) {
    return res.status(400).json({ errors });
  }
  next();
};

const validateTask = (req, res, next) => {
  const { title, content, category, priority, tags, status, date } = req.body;
  let errors = {};
  if (!title) errors.title = "Title is required";
  if (!content) errors.content = "Content is required";
  if (!category) errors.category = "Category is required";
  if (!priority) errors.priority = "Priority is required";
  if (!tags) errors.tags = "Tags are required";
  if (!status) errors.status = "Status is required";
  if (!date) errors.date = "Date is required";

  if (Object.keys(errors).length > 0) {
    return res.status(400).json({ errors });
  }
  next();
};

// Authentication middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(403).json({ message: "No token provided" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded; // Attach decoded payload (should contain email)
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// Routes
app.post("/register", validateRegistration, async (req, res) => {
  const { name, email, password, phone, age, address } = req.body;
  const users = readData("users.json");
  if (users.find((user) => user.email === email)) {
    return res.status(400).json({ message: "User already exists" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ name, email, password: hashedPassword, phone, age, address });
    writeData("users.json", users);
    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "12h" });
    res.status(201).json({ token });
  } catch (err) {
    res.status(500).json({ message: "Error hashing password", error: err.message });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }
  const users = readData("users.json");
  const user = users.find((u) => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid credentials" });
  }
  const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "12h" });
  res.json({ token });
});

// CRUD: Tasks
app.get("/tasks", authenticate, (req, res) => {
  const tasks = readData("tasks.json").filter((task) => task.email === req.user.email);
  res.json(tasks);
});

app.get("/tasks/:id", authenticate, (req, res) => {
  const taskId = req.params.id;
  const tasks = readData("tasks.json");
  const task = tasks.find((t) => t.id == taskId && t.email === req.user.email);
  if (!task) return res.status(404).json({ message: "Task not found" });
  res.json(task);
});

app.post("/tasks", authenticate, validateTask, (req, res) => {
  const { title, content, category, priority, tags, status, date } = req.body;
  const tasks = readData("tasks.json");
  const newTask = {
    id: Date.now(),
    email: req.user.email,
    title,
    content,
    category,
    priority,
    tags,
    status: status || "pending", // Default status if not provided
    date: date || new Date().toISOString(), // Default to current date if not provided
  };
  tasks.push(newTask);
  writeData("tasks.json", tasks);
  res.json(newTask);
});

app.put("/tasks/:id", authenticate, validateTask, (req, res) => {
  let tasks = readData("tasks.json");
  const taskIndex = tasks.findIndex((t) => t.id == req.params.id && t.email === req.user.email);
  if (taskIndex === -1) return res.status(404).json({ message: "Task not found" });
  tasks[taskIndex] = { ...tasks[taskIndex], ...req.body };
  writeData("tasks.json", tasks);
  res.json(tasks[taskIndex]);
});

app.delete("/tasks/:id", authenticate, (req, res) => {
  let tasks = readData("tasks.json");
  const newTasks = tasks.filter((t) => t.id != req.params.id || t.email !== req.user.email);
  writeData("tasks.json", newTasks);
  res.json({ message: "Task deleted" });
});

app.delete("/tasks", authenticate, (req, res) => {
  let tasks = readData("tasks.json");
  tasks = tasks.filter((task) => task.email !== req.user.email);
  writeData("tasks.json", tasks);
  res.json({ message: "All your tasks have been deleted." });
});

// Delete user account
app.delete("/delete-account", authenticate, (req, res) => {
  if (!req.user || !req.user.email) {
    return res.status(400).json({ message: "Invalid user. Cannot delete account." });
  }

  // Remove user from users.json
  let users = readData("users.json");
  users = users.filter((u) => u.email !== req.user.email);
  writeData("users.json", users);

  // Remove all tasks for this user
  let tasks = readData("tasks.json");
  tasks = tasks.filter((task) => task.email !== req.user.email);
  writeData("tasks.json", tasks);

  res.json({ message: "Account and all associated tasks deleted." });
});

// Add debug endpoints to view all tasks and users
app.get('/debug/tasks', (req, res) => {
  res.json(readData('tasks.json'));
});
app.get('/debug/users', (req, res) => {
  res.json(readData('users.json'));
});

// Add a route for the root URL
app.get("/", (req, res) => {
  res.send("Welcome to my server!");
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
