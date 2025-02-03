const express = require("express");
const passport = require("passport");
const BasicStrategy = require("passport-http").BasicStrategy;
const JwtStrategy = require("passport-jwt").Strategy;
const extractJwt = require("passport-jwt").ExtractJwt;
const jwt = require("jsonwebtoken");
const bodyParser = require("express").json();
const app = express();
const port = 3000;

app.use(bodyParser);

const programmingQuotes = [
  {
    quote:
      "Any fool can write code that a computer can understand. Good programmers write code that humans can understand. - Martin Fowler",
  },
  { quote: "First, solve the problem. Then, write the code. - John Johnson" },
  {
    quote:
      "Experience is the name everyone gives to their mistakes. - Oscar Wilde",
  },
  {
    quote:
      "In order to be irreplaceable, one must always be different. - Coco Chanel",
  },
  { quote: "Java is to JavaScript what car is to Carpet. - Chris Heilmann" },
];

const users = {
  user: { username: "user", password: "password", role: "user" },
  admin: { username: "admin", password: "password", role: "admin" },
};

const blacklist = [];
const SECRET_KEY = "mysecret";
const REFRESH_SECRET = "refreshsecret";

const jwtOptions = {
  jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: SECRET_KEY,
};

// Basic Auth for Sign-In
passport.use(
  new BasicStrategy((username, password, done) => {
    const user = users[username];
    if (user && user.password === password) {
      return done(null, { username: user.username, role: user.role });
    }
    return done(null, false);
  })
);

// JWT for Auth
passport.use(
  new JwtStrategy(jwtOptions, (payload, done) => {
    if (blacklist.includes(payload.jti)) {
      return done(null, false);
    }
    return done(null, payload);
  })
);

// Middleware to auth admin
const authorizeAdmin = (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    return next();
  }
  return res.status(403).json({ message: "Forbidden: Admin access required" });
};

// Gen Access + Refresh Tokens
const generateTokens = (user) => {
  const payload = { username: user.username, role: user.role };
  const accessToken = jwt.sign(payload, SECRET_KEY, { expiresIn: "15m" });
  const refreshToken = jwt.sign(payload, REFRESH_SECRET, { expiresIn: "7d" });
  return { accessToken, refreshToken };
};

// Middleware to verify refresh token
const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, REFRESH_SECRET);
  } catch (err) {
    return null;
  }
};

// Middleware check token expire & refresh
const checkToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ message: "No token provided" });

  const token = authHeader.split(" ")[1]; // Extract the actual token

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    req.user = decoded;
    next();
  });
};

// Middleware check if token  blacklisted
const checkBlacklist = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (blacklist.includes(token)) {
    return res
      .status(401)
      .json({ message: "Token is blacklisted" + " --- " + blacklist });
  }
  next();
};

app.use(checkBlacklist);

// Logout + Blacklist Token
const logout = (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (token) {
    blacklist.push(token);
  }
  res.json({ message: "Logged out successfully" });
};

// Sign In
app.post(
  "/signIn",
  passport.authenticate("basic", { session: false }),
  (req, res) => {
    const user = users[req.user.username];
    if (user) {
      const tokens = generateTokens(user);
      res.json(tokens);
    } else {
      res.status(401).json({ message: "Unauthorized" });
    }
  }
);

// Check Token
app.post(
  "/tokenStatus",
  passport.authenticate("jwt", { session: false }),
  checkToken,
  (req, res) => {
    res.json({ message: "Token is valid", user: req.user });
  }
);

// Refresh Token
app.post("/refreshToken", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(400).json({ message: "Refresh token required" });

  const decoded = verifyRefreshToken(refreshToken);
  if (!decoded)
    return res.status(403).json({ message: "Invalid refresh token" });

  const tokens = generateTokens({
    username: decoded.username,
    role: decoded.role,
  });
  res.json(tokens);
});

// Get Posts - user & admin Access
app.get(
  "/posts",
  passport.authenticate("jwt", { session: false }),
  checkToken,
  (req, res) => {
    res.json(programmingQuotes);
  }
);

// Add Post - Admin access
app.post(
  "/posts",
  passport.authenticate("jwt", { session: false }),
  checkToken,
  authorizeAdmin,
  (req, res) => {
    if (!req.body.quote) {
      return res.status(400).json({ message: "Quote text is required" });
    }
    programmingQuotes.push({ quote: req.body.quote });
    res.json({ message: "New quote added" });
  }
);

// Logout
app.post(
  "/logout",
  passport.authenticate("jwt", { session: false }),
  logout,
  (req, res) => {
    res.json({ message: "Logged out successfully" + blacklist });
  }
);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
