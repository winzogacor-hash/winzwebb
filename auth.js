const bcrypt = require("bcrypt");

/*
|--------------------------------------------------------------------------

AUTH CONFIG
*/

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

/*
|--------------------------------------------------------------------------

CHECK LOGIN
*/

async function authenticate(username, password) {

if (
    typeof username !== "string" ||
    typeof password !== "string"
) {
    return false;
}

// Username dibandingkan secara exact
if (username !== ADMIN_USERNAME) {
    return false;
}

// Password dibandingkan dengan hash
const validPassword = await bcrypt.compare(
    password,
    ADMIN_PASSWORD_HASH
);

return validPassword;

}

/*
|--------------------------------------------------------------------------

CREATE AUTH SESSION
*/

function createSession(req, username) {

req.session.authenticated = true;
req.session.username = username;
req.session.loginTime = Date.now();

}

/*
|--------------------------------------------------------------------------

CHECK AUTHENTICATION
*/

function isAuthenticated(req) {

return (
    req.session &&
    req.session.authenticated === true
);

}

/*
|--------------------------------------------------------------------------

REQUIRE AUTHENTICATION
*/

function requireAuth(req, res, next) {

if (!isAuthenticated(req)) {

    return res.status(401).json({
        success: false,
        message: "Unauthorized"
    });
}

next();

}

/*
|--------------------------------------------------------------------------

LOGOUT
*/

function logout(req) {

return new Promise((resolve) => {

    req.session.destroy(() => {
        resolve();
    });

});

}

/*
|--------------------------------------------------------------------------

EXPORT
*/

module.exports = {
authenticate,
createSession,
isAuthenticated,
requireAuth,
logout
};