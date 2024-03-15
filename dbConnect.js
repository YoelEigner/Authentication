const sql = require("mssql");

const config = {
    user: "Node",
    password: process.env.DBPASS,
    server: "localhost\\SQLEXPRESS",
    database: "nodelogin",
    port: 1433,
    options: {
        trustedConnection: false,
        trustServerCertificate: true
    }
};

exports.getUser = async (username) => {
    try {
        await sql.connect(config);
        let resp = await sql.query(`SELECT * FROM [nodelogin].[dbo].[users] WHERE username ='${username}'`)
        return resp.recordset;
    } catch (err) {
        console.log(err);
    }
}
exports.registerUser = async (username, password) => {
    try {
        await sql.connect(config);
        let resp = await sql.query(`UPDATE [nodelogin].[dbo].[USERS] SET password = '${password}' WHERE username ='${username}'`)
        return resp.rowsAffected;
    } catch (err) {
        console.log(err);
    }
}

exports.getRefreshTokens = async (refreshToken) => {
    try {
        await sql.connect(config);
        let resp = await sql.query(`SELECT refreshToken FROM [nodelogin].[dbo].[refreshTokens] WHERE refreshToken = '${refreshToken}'`)
        return resp.recordset;
    } catch (err) {
        console.log(err);
    }
}

exports.updateRefreshTokens = async (refreshToken) => {
    try {
        await sql.connect(config);
        let resp = await sql.query(`INSERT INTO [dbo].[refreshTokens] VALUES ('${refreshToken}')`)
        return resp.rowsAffected;
    } catch (err) {
        console.log(err);
    }
}