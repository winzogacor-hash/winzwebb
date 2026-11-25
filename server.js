const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

/*
|--------------------------------------------------------------------------

BASIC SECURITY
*/

app.disable("x-powered-by");

app.use(
helmet({
contentSecurityPolicy: false
})
);

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

/*
|--------------------------------------------------------------------------

SESSION
*/

app.use(
session({
secret: process.env.SESSION_SECRET,
resave: false,
saveUninitialized: false,

    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 1000 * 60 * 60
    }
})

);

/*
|--------------------------------------------------------------------------

LOGIN RATE LIMIT
*/

const loginLimiter = rateLimit({
windowMs: 15 * 60 * 1000,
max: 5,

standardHeaders: true,
legacyHeaders: false,

message: {
    success: false,
    message: "Terlalu banyak percobaan login. Coba lagi nanti."
}

});

/*
|--------------------------------------------------------------------------

PASSWORD
*/

const username = process.env.ADMIN_USERNAME;
const passwordHash = process.env.ADMIN_PASSWORD_HASH;

/*
|--------------------------------------------------------------------------

ACTIVITY LOG
*/

const activityLogs = [];

function addLog(type, message, req) {
activityLogs.unshift({
type,
message,
ip: req.ip,
time: new Date().toISOString()
});

// Batasi memory agar tidak terus membesar
if (activityLogs.length > 200) {
    activityLogs.pop();
}

}

/*
|--------------------------------------------------------------------------

AUTH MIDDLEWARE
*/

function requireAuth(req, res, next) {
if (!req.session.authenticated) {
return res.status(401).json({
success: false,
message: "Unauthorized"
});
}

next();

}

/*
|--------------------------------------------------------------------------

LOGIN API
*/

app.post("/api/login", loginLimiter, async (req, res) => {
try {
const { username: inputUsername, password } = req.body;

    if (
        typeof inputUsername !== "string" ||
        typeof password !== "string"
    ) {
        addLog("security", "Invalid login request", req);

        return res.status(400).json({
            success: false,
            message: "Input tidak valid."
        });
    }

    if (inputUsername !== username) {
        addLog("failed_login", "Username tidak valid", req);

        return res.status(401).json({
            success: false,
            message: "Username atau password salah."
        });
    }

    const validPassword = await bcrypt.compare(
        password,
        passwordHash
    );

    if (!validPassword) {
        addLog("failed_login", "Password salah", req);

        return res.status(401).json({
            success: false,
            message: "Username atau password salah."
        });
    }

    req.session.authenticated = true;
    req.session.username = username;

    addLog("login", "Login berhasil", req);

    return res.json({
        success: true,
        message: "Login berhasil."
    });

} catch (error) {
    console.error(error);

    return res.status(500).json({
        success: false,
        message: "Internal server error."
    });
}

});

/*
|--------------------------------------------------------------------------

CHECK SESSION
*/

app.get("/api/session", requireAuth, (req, res) => {
res.json({
authenticated: true,
username: req.session.username
});
});

/*
|--------------------------------------------------------------------------

ACTIVITY LOG API
*/

app.get("/api/activity", requireAuth, (req, res) => {
res.json({
success: true,
logs: activityLogs
});
});

/*
|--------------------------------------------------------------------------

LOGOUT
*/

app.post("/api/logout", requireAuth, (req, res) => {
const username = req.session.username;

req.session.destroy(() => {
    addLog("logout", `Logout: ${username}`, req);

    res.json({
        success: true,
        message: "Logout berhasil."
    });
});

});

/*
|--------------------------------------------------------------------------

DASHBOARD PROTECTION
*/

app.get("/dashboard.html", (req, res, next) => {
if (!req.session.authenticated) {
return res.redirect("/login.html");
}

next();

});

/*
|--------------------------------------------------------------------------

STATIC FILES
*/

app.use(express.static(path.join(__dirname, "public")));

/*
|--------------------------------------------------------------------------

SECURITY: UNKNOWN API ROUTE
*/

app.use("/api", (req, res) => {
addLog(
"security",
"Unknown API endpoint: ${req.method} ${req.path}",
req
);

res.status(404).json({
    success: false,
    message: "API endpoint not found."
});

});

/*
|--------------------------------------------------------------------------

404
*/

app.use((req, res) => {
res.status(404).send("404 - Page Not Found");
});

/*
|--------------------------------------------------------------------------

START SERVER
*/

app.listen(PORT, () => {
console.log("=================================");
console.log(" WINZ SECURITY SERVER");
console.log("=================================");
console.log("Server running on port ${PORT}");
});