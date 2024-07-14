const express = require("express");
const Datastore = require("nedb-promises");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("./config");

const app = express();

app.use(express.json());

const users = Datastore.create("Users.db");

app.get("/", (req, res) => {
  res.send("REST API Authentication & Authorization");
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res
        .status(422)
        .json({ message: "Please Fill in All Fields (Name, Email, Password)" });
    }

    if (await users.findOne({ email: email })) {
      return res.status(409).json({ message: "email already exist" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await users.insert({
      name,
      email,
      password: hashedPassword,
      role: role ?? "member",
    });

    return res
      .status(201)
      .json({ message: "User Registered successfully", id: newUser._id });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(422)
        .json({ message: "Please Fill in all fields (email & password)" });
    }

    const user = await users.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Email or password is invalid" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Email or password is invalid" });
    }

    const accessToken = jwt.sign(
      { userId: user._id },
      config.accessTokenSecret,
      { subject: "accessApi", expiresIn: "1h" }
    );

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      accessToken,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.get("/api/users/current", ensureAuth, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user.id });

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.get("/api/admin", ensureAuth, authorize(["admin"]), (req, res) => {
  return res.status(200).json({ message: "Only Admins can access this route" });
});

app.get(
  "/api/moderator",
  ensureAuth,
  authorize(["admin", "moderator"]),
  (req, res) => {
    return res
      .status(200)
      .json({ message: "Only Admins adn Moderators can access this route" });
  }
);

async function ensureAuth(req, res, next) {
  const accessToken = req.headers.authorization;

  if (!accessToken) {
    return res.status(401).json({ message: "Access Token Not Found" });
  }

  try {
    const decodedAccessToken = jwt.verify(
      accessToken,
      config.accessTokenSecret
    );

    req.user = { id: decodedAccessToken.userId };
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid Access Token" });
  }
}

function authorize(roles = []) {
  return async function (req, res, next) {
    const user = await users.findOne({ _id: req.user.id });

    if (!user || !roles.includes(user.role)) {
      return res.status(403).json({ message: "Access Denied" }); 
    }

    next();
  };
}

app.listen(3000, () => console.log("Server started on port 3000"));
