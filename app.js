const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");
const { response } = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dbPath = path.join(__dirname, "userData.db");

const app = express();
app.use(express.json());
app.use(cors());

let dataBase = null;
let port;

const initializeDbAndServer = async () => {
	try {
		dataBase = await open({
			filename: dbPath,
			driver: sqlite3.Database,
		});
		port = process.env.PORT || 9000;
		app.listen(port, () =>
			console.log(`server Running at http://localhost:${port}/`)
		);
	} catch (error) {
		console.log(`DB Error: ${error.message}`);
		process.exit(1);
	}
};

initializeDbAndServer();

const authenticateToken = (request, response, next) => {
	let jwtToken;
	const authHeader = request.headers["authorization"];

	if (authHeader !== undefined) {
		jwtToken = authHeader.split(" ")[1];
	}
	if (jwtToken === undefined) {
		response.status(401);
		response.send("Invalid JWT token");
	} else {
		jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
			if (error) {
				response.status(401);
				response.send("Invalid JWT Token");
			} else {
				request.username = payload.username;
				next();
			}
		});
	}
};

const validatePassword = (password) => {
	return password.length > 8;
};

app.post("/register", async (request, response) => {
	const { username, name, password, gender, location } = request.body;
	const hashedPassword = await bcrypt.hash(password, 10);
	const selectUserQuery = `SELECT * FROM user WHERE username = '${username}';`;
	const dataBaseUser = await dataBase.get(selectUserQuery);

	if (dataBaseUser === undefined) {
		const createUserQuery = `
        INSERT INTO user (username, name, password, gender,location) VALUES ( '${username}','${name}','${hashedPassword}','${gender}','${location}');`;
		if (validatePassword(password)) {
			await dataBase.run(createUserQuery);
			response.send("User created successfully");
		} else {
			response.status(400);
			response.send("Password is too short");
		}
	} else {
		response.status(400);
		response.send("User already exists");
	}
});

app.post("/login", async (req, res) => {
	const { username, password } = req.body;
	const selectUserQuery = `SELECT * FROM user WHERE username = '${username}';`;
	const dataBaseUser = await dataBase.get(selectUserQuery);

	if (dataBaseUser === undefined) {
		res.status(400);
		res.send("Invalid User");
	} else {
		const isPasswordMatched = await bcrypt.compare(
			password,
			dataBaseUser.password
		);
		if (isPasswordMatched) {
			const payload = { username };
			const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
			res.send({ jwtToken });
		} else {
			res.status(400);
			res.send("Invalid password");
		}
	}
});

app.put("/change-password", authenticateToken, async (req, res) => {
	const { username, oldPassword, newPassword } = req.body;
	const selectUserQuery = `SELECT * FROM user WHERE username = '${username}';`;
	const dataBaseUser = await dataBase.get(selectUserQuery);
	if (dataBaseUser === undefined) {
		response.status(400);
		response.send("Invalid user");
	} else {
		const isPasswordMatched = await bcrypt.compare(
			oldPassword,
			dataBaseUser.password
		);
		if (isPasswordMatched) {
			if (validatePassword(newPassword)) {
				const hashedPassword = await bcrypt.hash(newPassword, 10);
				const updatePasswordQuery = `UPDATE user SET password = '${hashedPassword}' WHERE username='${username}';`;
				const user = await dataBase.run(updatePasswordQuery);

				res.send("Password updated");
			} else {
				res.status(400);
				res.send("Password is too short");
			}
		} else {
			res.status(400);
			res.send("Invalid current password");
		}
	}
});

module.exports = app;
