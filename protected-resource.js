const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const { timeout } = require("./utils")
const jwt = require("jsonwebtoken")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/

app.get('/user-info', function(req,res){
	if (req.headers.authorization == null) {
		return res.sendStatus(401);
	}
	let authorizationToken = req.headers.authorization.slice(7);
	try {
		let decoded = jwt.verify(authorizationToken, config.publicKey, ["RS256"])
		let username = decoded.userName;
		let user = username in users ? users[username] : undefined;
		let result = {}
		for (let scope of decoded.scope.split(" ")) {
			let permission = scope.slice(11);
			if (permission in user) {
				result[permission] = user[permission]
			}
		}
		return res.json(result);
	} catch (err) {
		return res.sendStatus(401);
	}
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
