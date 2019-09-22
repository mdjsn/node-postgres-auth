const express = require("express"),
  { Client } = require("pg"),
  { hash, compare } = require("bcryptjs"),
  { sign, verify } = require("jsonwebtoken"),
  cors = require("cors"),
  cookieParser = require("cookie-parser"),
  bodyParser = require("body-parser");

const config = require("./configuration/config")

const app = express(),
  corsOption = {
    origin: true,
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true,
    exposedHeaders: ["x-auth-token"]
  };

const port = process.env.PORT || 5000;

//Define Postgres parameters
let connectionString = "postgresql://localhost/tutorial";
const client = new Client({
  connectionString: connectionString,
  ssl: true
});
client.connect();

app.use(cors(corsOption));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/api/token",
  function (req, res) {
    if (!req.headers.authorization) {
      return res.send(401, "Authentication error. Token not entered");
    } else {
      const result = verify({ email: req.body.user.email }, process.env.app_secret)
      if (!result) {
        return res.send(401, "Authentication error. Token not entered or invalid");
      } else {
        // Can use the result value email to fetch the users data from database
        return res.json({
          data: result
        });
      }
    }
  });

app.post(
  "/api/auth/signup",
  function (req, res) {
    if (!req.body.user) {
      return res.send(401, "Authentication error. Invalid Credentials");
    } else {
      client.query(
        "SELECT * from users where email = $1",
        [req.body.user.email],
        async function (err, rows) {
          if (err) throw err;
          if (rows && rows.rowCount === 0) {
            console.log("There is no such user, adding now");
            const hashedPassword = await hash(req.body.user.password, 10);
            client.query(
              "INSERT into users(email,name,password) VALUES($1, $2. $3)",
              [req.body.user.email, req.body.user.name, hashedPassword]
            );
            return {
              token: sign({ email: req.body.user.email }, process.env.app_secret)
            };
          } else {
            console.log("User already exists in database");
          }
        }
      );
    }
  }
);

app.post(
  "/api/auth/login",
  function (req, res) {
    if (!req.body.user) {
      return res.send(401, "Authentication error. Invalid Credentials");
    } else {
      client.query(
        "SELECT * from users where email = $1",
        [req.body.user.email],
        async function (err, rows) {
          if (err) throw err;
          if (rows && rows.rowCount === 0) {
            console.log("There is no such user");
          } else {
            console.log("User exists in database");
            const passwordValid = await compare(req.body.user.password, rows.password);
            if (!passwordValid) {
              console.log("Invalid password");
            } else {
              return {
                token: sign({ email: req.body.user.email }, APP_SECRET)
              };
            }
          }
        }
      );
    }
  }
);

app.listen(port, () => console.log(`Listening on port ${port}`));