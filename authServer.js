const express = require('express')
const cors = require('cors');
require('dotenv').config()
var bcrypt = require('bcryptjs');
const app = express()
app.use(express.json())

// app.use(cors())
app.use(cors({
    origin: '*'
}));
// app.options('*', cors());

const jwt = require('jsonwebtoken');
const { registerUser, getUser, getRefreshTokens, updateRefreshTokens } = require('./dbConnect');
// const fs = require('fs');
// const https = require('https');



// const options = {
//     key: fs.readFileSync('./certificates/server.key'),
//     cert: fs.readFileSync('./certificates/server.cert.pem')
// };

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
            let refreshTokens = await getRefreshTokens(refreshToken)
            let tokenArr = refreshTokens.map(x => x.refreshToken)
            if (tokenArr.length === 0) {
                await updateRefreshTokens(refreshToken)
            }
            const expiresInMilliseconds = 43200000;
            const expiresAt = new Date(Date.now() + expiresInMilliseconds);
            
            res.json({ accessToken: accessToken, refreshToken: refreshToken, authenticated: true, username: req.body.username, expiresIn: expiresInMilliseconds, expiresAt: expiresAt.toISOString() })
        } else {
            res.status(400).send('Incorrect Password')
        }

    } catch (error) {
        res.status(500).send()
    }
})



app.post('/api/token', async (req, res) => {
    const refreshToken = req.body.token
    let refreshTokens = await getRefreshTokens(refreshToken)
    let tokenArr = refreshTokens.map(x => x.refreshToken)
    if (refreshToken === null) return res.sendStatus(401)
    if (!tokenArr.includes(refreshToken)) return res.sendStatus(403)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken })
    })
})

app.post('/api/changepass', async (req, res) => {
    try {
        let resp = await getUser(req.body.username)

        let checkIsUser = await getUser(req.body.username)
        if (checkIsUser.length === 0) { res.status(500).send(`Username Incorrect, please try again!`) }
        else if (checkIsUser.length === 1 && await bcrypt.compare(req.body.oldpassword, resp[0].password)) {
            const hashedPassword = await bcrypt.hash(req.body.newpassword, 10)
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

const generateAccessToken = (user) => {
    return jwt.sign({ name: user }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '12h' });

}
app.listen(8000)