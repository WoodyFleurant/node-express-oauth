const fs = require("fs")
const url = require("url")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get('/authorize', function(req,res){
	let request_id = randomString();
	requests[request_id] = req.query;
	let clientID = req.query["client_id"];
	let scope = req.query.scope;
	let validClient = clientID in clients;
	let validScopes = validClient ? clients[clientID].scopes.includes(scope) : false;
	let valid = validClient && validScopes;
	if (valid) {
		res.status(200);
		return res.render("login", {
			"client": clients[clientID],
			"scope": scope,
			"requestId": request_id
		});
	}
	return res.sendStatus(401);
});

app.post('/approve', function(req,res){
	const { userName, password, requestId } = req.body
	if (!userName || users[userName] !== password) {
		res.status(401).send("Error: user not authorized")
		return
	}
	const clientReq = requests[requestId]
	delete requests[requestId]
	if (!clientReq) {
		res.status(401).send("Error: invalid user request")
		return
	}
	const code = randomString()
	authorizationCodes[code] = {
		"clientReq": clientReq,
		"userName": userName
	}
	let testUrl = new URL(clientReq.redirect_uri)
	testUrl.searchParams.append("code", code)
	testUrl.searchParams.append("state", clientReq.state)
	res.redirect(url.format(testUrl))
})

app.post('/token', function (req,res) {
	if (req.headers.authorization == null) {
		res.status(401).send("Error: user not authorized")
		return
	}
	const {clientId, clientSecret} = decodeAuthCredentials(req.headers.authorization)
	if (clients[clientId].clientSecret !== clientSecret) {
		res.status(401).send("Error: user not authorized")
		return
	}
	if (req.body.code == null){
		res.status(401).send("Error: user not authorized")
		return
	}
	if (authorizationCodes[req.body.code] == null) {
		res.status(401).send("Error: user not authorized")
		return
	}
	const code = authorizationCodes[req.body.code]
	delete authorizationCodes[req.body.code]
	const body = {
		"userName": code.userName,
		"scope": code.clientReq.scope
	}
	const accessToken = jwt.sign(body, config.privateKey, { algorithm: 'RS256'})
	return res.status(200).json({
		"access_token": accessToken,
		"token_type": "Bearer"
	});
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
