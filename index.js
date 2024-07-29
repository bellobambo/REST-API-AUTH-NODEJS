const express = require("express");
const Datastore = require("nedb-promises");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("./config");

const app = express();

app.use(express.json());

const users = Datastore.create("Users.db");

const userRefreshTokens = Datastore.create("UserRefreshTokens.db");

const userInvalidTokens = Datastore.create("UserInvalidTokens.db");

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
        .json({ message: "Please fill in all fields (email & password)" });
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
      { subject: "accessApi", expiresIn: config.accessTokenExpiresIn }
    );

    const newRefreshToken = jwt.sign(
      { userId: user._id },
      config.refreshTokenSecret,
      { subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn }
    );

    await userRefreshTokens.insert({
      refreshToken: newRefreshToken,
      userId: user._id,
    });

    return res.status(200).json({
      accessToken,
      refreshToken: newRefreshToken,
      id: user._id,
      name: user.name,
      email: user.email,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.post("/api/auth/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token not found" });
    }

    const decodedRefreshToken = jwt.verify(
      refreshToken,
      config.refreshTokenSecret
    );

    const userRefreshToken = await userRefreshTokens.findOne({
      refreshToken,
      userId: decodedRefreshToken.userId,
    });

    if (!userRefreshToken) {
      return res
        .status(401)
        .json({ message: "Refresh Token invalid or expired" });
    }

    await userRefreshTokens.remove({ _id: userRefreshToken._id });

    const newAccessToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      config.accessTokenSecret,
      { expiresIn: config.accessTokenExpiresIn }
    );

    const newRefreshToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      config.refreshTokenSecret,
      { expiresIn: config.refreshTokenExpiresIn }
    );

    await userRefreshTokens.insert({
      refreshToken: newRefreshToken,
      userId: decodedRefreshToken.userId,
    });

    return res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    if (
      error instanceof jwt.TokenExpiredError ||
      error instanceof jwt.JsonWebTokenError
    ) {
      return res
        .status(401)
        .json({ message: "Refresh Token invalid or expired" });
    }
    return res.status(500).json({ message: error.message });
  }
});

app.get("/api/auth/logout", ensureAuth, async (req, res) => {
  try {
    await userRefreshTokens.removeMany({ userId: req.user.id });
    await userRefreshTokens.compactDatafile();

    await userInvalidTokens.insert({
      accessToken: req.accessToken.value,
      userId: req.user.id,
      expirationTime: req.accessToken.exp,
    });

    return res.status(204).send();
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Refresh Token invalid or expired" });
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

  if (await userInvalidTokens.findOne({ accessToken })) {
    return res
      .status(401)
      .json({ message: "Access Token invalid", code: "AccessTokenInvalid" });
  }

  try {
    const decodedAccessToken = jwt.verify(
      accessToken,
      config.accessTokenSecret
    );

    req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };
    req.user = { id: decodedAccessToken.userId };
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res
        .status(401)
        .json({ message: "Access Token Expired", code: "AccessTokenExpired" });
    } else if (error instanceof jwt.JsonWebTokenError) {
      return res
        .status(401)
        .json({ message: "Access Token invalid", code: "AccessTokenInvalid" });
    } else {
      return res.status(500).json({ message: error.message });
    }
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
