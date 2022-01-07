const passport = require('passport')
const localStrategy = require('local-strategy')
const User = require('../model/User')

passport.use("signup", new localStrategy({
    usernameField: "email", //cambia los valores por defecto
    passwordField: "password"
}, async (email, password, done) => {
    try {
        const user = await User.create({ email, password})
        return done(null, user)
    } catch (e) {
        done(e) //callback verificador
    }
}))


password.use("login", new localStrategy({
    usernameField: "email",
    passwordField: "password"
}, async (email, password, done) => {
    try {
        const user = await User.findOne({ email })
        if (!user){
            return done(null, false, { message: "User not found"}) //valida si el usuario existe
        }

        const validate = await user.isValidPassword(password)

        if (!validate) {
            return done(null, false, {message: "wrong password"}) // en caso de existir valida si el password es el correcto
        }

        return done(null, user, { message: "login success"}) // usuario logeado correctamente
    } catch (e) {
        return done(e)
    }
}))

passport.use(new JWTStrategy({
    secretOrKey: 'top_secret',
    jwtFromRequest: ExtractJWT.fromUrlQueryParameter('secret_token')
}, async (token, done) => {
    try {
        return done(null, token.user)
    } catch (e) {
        done(error)
    }
}))