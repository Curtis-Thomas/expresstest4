const express = require('express');
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;
const JwtStrategy = require('passport-jwt').Strategy;
const extractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

const programmingQuotes = [
    { quote: "Any fool can write code that a computer can understand. Good programmers write code that humans can understand. - Martin Fowler" },
    { quote: "First, solve the problem. Then, write the code. - John Johnson" },
    { quote: "Experience is the name everyone gives to their mistakes. - Oscar Wilde" },
    { quote: "In order to be irreplaceable, one must always be different. - Coco Chanel" },
    { quote: "Java is to JavaScript what car is to Carpet. - Chris Heilmann" },
    { quote: "Knowledge is power. - Francis Bacon" },
    { quote: "Sometimes it pays to stay in bed on Monday, rather than spending the rest of the week debugging Monday’s code. - Dan Salomon" },
    { quote: "Perfection is achieved not when there is nothing more to add, but rather when there is nothing more to take away. - Antoine de Saint-Exupery" },
    { quote: "Ruby is rubbish! PHP is phpantastic! - Nikita Popov" },
    { quote: "Code is like humor. When you have to explain it, it’s bad. - Cory House" },
    { quote: "Fix the cause, not the symptom. - Steve Maguire" },
    { quote: "Optimism is an occupational hazard of programming: feedback is the treatment. - Kent Beck" },
    { quote: "When to use iterative development? You should use iterative development only on projects that you want to succeed. - Martin Fowler" },
    { quote: "Simplicity is the soul of efficiency. - Austin Freeman" },
    { quote: "Before software can be reusable it first has to be usable. - Ralph Johnson" }
];

const generateRandomQuote = () => {
    const randomIndex = Math.floor(Math.random() * programmingQuotes.length);
    return programmingQuotes[randomIndex];
};

const users = {
    user: { username: "user", password: "password", role: "user" },
    admin: { username: "admin", password: "password", role: "admin" }
};

const blacklist = [];

const MYSECRETJWTKEY = "mysecret";

const optionsForJwtValidation = {
    jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: MYSECRETJWTKEY
};

passport.use(new BasicStrategy(function (username, password, done) {
    const user = users[username];

    if (user && user.password === password) {
        return done(null, { username: user.username, role: user.role });
    }
    return done(null, false);
}));

passport.use(new JwtStrategy(optionsForJwtValidation, function (payload, done) {
    if (payload.username && payload.role) {
        return done(null, payload);
    }
    return done(null, false);
}));

const authorizeAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        return next();
    }
    res.status(403).json({ message: "Forbidden: Admin access required" });
};

const generateToken = (user) => jwt.sign({ username: user.username, role: user.role }, MYSECRETJWTKEY, { expiresIn: '30m' });

const checkToken = (req, res, next) => {
    if(blacklist.includes(req.headers['authorization'])) {
        return res.status(401).json({ message: "Unauthorized: Token is blacklisted" });
    }
    if (req.user.exp < Date.now()) {
        //refresh
        const newToken = generateToken(req.user);
        res.set('Authorization', newToken);
    }
    next();
}

const logout = (req, res) => {
   
    blacklist.push(req.headers['authorization']);
 
    res.setHeader('Authorization', '');


    res.json({ blacklist ,message: "Logged out successfully" });
};

app.post('/signInUser',
    passport.authenticate('basic', { session: false }),
    (req, res) => {
        res.json({ token: generateToken(req.user) });
    }
);

app.post('/signInAdmin',
    passport.authenticate('basic', { session: false }),
    authorizeAdmin,
    (req, res) => {
        res.json({ token: generateToken(req.user) });
    }
);

app.post('/tokenStatus',
    passport.authenticate('jwt', { session: false }),
    checkToken,
    (req, res) => {
        const tokenExpirationTime = new Date(req.user.exp * 1000);
        res.json({ message: "Token is valid", user: req.user, expiresAt: tokenExpirationTime });
    }
)

app.get('/protectedWithJWT',
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
        res.send('Yay, valid token!!');
    }
);

app.get('/posts',
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
        const quote = generateRandomQuote();
        res.json(quote);
    }
);

//if admin role, can add new quotes
app.post('/posts',
    passport.authenticate('jwt', { session: false }),
    checkToken,
    authorizeAdmin,
    (req, res) => {
        programmingQuotes.push(req.body);
        res.json({ message: "New quote added" });
    }
);



app.post('/logout',
    passport.authenticate('jwt', { session: false }),
    checkToken,
    (req, res) => {
        logout(req, res);
    }
);


app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});
