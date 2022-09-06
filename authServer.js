const express = require('express')
const cors = require('cors');
require('dotenv').config()
var bcrypt = require('bcryptjs');
const app = express()
const jwt = require('jsonwebtoken');
const { registerUser, getUser } = require('./dbConnect');
app.use(cors())
app.use(express.json())

//store in database
let refreshTokens = []

app.post('/api/register', async (req, res) => {
    try {
        let checkIsUser = await getUser(req.body.username)
        if (checkIsUser.length === 0) { res.status(500).send(`Username not found, please speak to your administrator!`) }
        else if (checkIsUser.length === 1 && checkIsUser[0].password === req.body.oldPassword) {
            const hashedPassword = await bcrypt.hash(req.body.password, 10)
            let resp = await registerUser(req.body.username, hashedPassword)
            if (resp >= 1) { res.status(200).send('success') }
            else { res.status(500).send('Unknown Error') }
        }
        else if (checkIsUser[0].password !== req.body.oldPassword) {
            res.status(500).send(`Old password incorrect, please try again!`)
        }
    } catch (error) {
        res.status(500).send()
    }
})


app.post('/api/login', async (req, res) => {
    let resp = await getUser(req.body.username)
    if (resp.length === 0) {
        return res.status(400).send('Incorrect Username')
    }
    try {
        if (await bcrypt.compare(req.body.password, resp[0].password)) {
            const accessToken = await generateAccessToken(resp[0].username)
            const refreshToken = jwt.sign(resp[0].username, process.env.REFRESH_TOKEN_SECRET)
            refreshTokens.push(refreshToken)
            res.json({ accessToken: accessToken, refreshToken: refreshToken, authenticated: true, username: req.body.username, expiresIn: 600000 })
        } else {
            res.status(400).send('Incorrect Password')
        }

    } catch (error) {
        res.status(500).send()
    }
})



app.post('/api/token', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken === null) return res.sendStatus(401)
    if (!refreshToken.includes(refreshToken)) return res.sendStatus(403)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, user) => {
        if (err) return res.sendStatus(403)
        const accessToken = await generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken })
    })
})

const generateAccessToken = async (user) => {
    return await jwt.sign({ name: user }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: 600000 });

}


app.listen(8000)