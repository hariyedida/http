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

app.get("/", (req, res) => {
	res.status(200);
	res.send("Running");
});

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
			response.status(200);
			response.send({ user_created: "User created successfully" });
		} else {
			response.status(400);
			response.send({ error_msg: "Password is too short" });
		}
	} else {
		response.status(400);
		response.send({ error_msg: "That username is taken. Try another" });
	}
});

app.post("/login", async (req, res) => {
	const { username, password } = req.body;
	const selectUserQuery = `SELECT * FROM user WHERE username = '${username}';`;
	const dataBaseUser = await dataBase.get(selectUserQuery);

	if (dataBaseUser === undefined) {
		res.status(400);
		res.send({ status_code: 400, error_msg: "Invalid username" });
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
			res.send({
				status_code: 400,
				error_msg: "username and password didn't match",
			});
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

app.post("/user-table/", authenticateToken, async (req, res) => {
	const { userData } = req.body;
	const { username } = req;
	const selectUserQuery = `PRAGMA TABLE_INFO(${username});`;
	const dataBaseUserTable = await dataBase.get(selectUserQuery);
	// console.log(username);

	const addDatatoDb = async () => {
		const values = userData.map(
			(eachBook) =>
				`(${eachBook.userId},${eachBook.id},"${eachBook.title}", "${eachBook.body}")`
		);
		const valuesString = values.join(",");
		const addDataQuery = `INSERT INTO ${username} (user_id,id,title,body) VALUES ${valuesString};`;
		const dbResponse = await dataBase.run(addDataQuery);
		res.status(200);
		res.send({ message: "Data added to DB" });
	};

	if (dataBaseUserTable === undefined) {
		const createUserInputTableQuery = `
	    CREATE TABLE ${username} (id INT, user_id INT, body VARCHAR(255), title VARCHAR(255));`;
		const createUserTableDb = await dataBase.run(createUserInputTableQuery);
		// console.log("table", createUserTableDb);
		const isTableCreated = await dataBase.get(selectUserQuery);
		addDatatoDb();
	} else {
		const deletePrevDataQuery = `DELETE FROM ${username}`;
		const deleteData = await dataBase.run(deletePrevDataQuery);
		addDatatoDb();
	}
});

app.get("/user-data", authenticateToken, async (req, res) => {
	const { username } = req;
	const dataQuery = `SELECT * FROM ${username}`;
	const data = await dataBase.all(dataQuery);
	res.send({ userData: data });
});

app.delete("/delete-data", authenticateToken, async (req, res) => {
	const { username } = req;
	const deleteDataQuery = `DELETE FROM ${username}`;
	const data = await dataBase.run(deleteDataQuery);
	res.status(200);
	res.send({ data_deleted: "data deleted from table" });
});

module.exports = app;
