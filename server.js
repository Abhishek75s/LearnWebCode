import express from 'express';
import Database from "better-sqlite3";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import "dotenv/config";
import cookieParser from 'cookie-parser';

// This creates or opens a file named 'database.db' in your project root
const db = new Database("database.db"); 
db.pragma("journal_mode = WAL");

// database setup here
const createTable = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
    `).run()
})

createTable();

const app = express();

// Its a template view which can be rendered as a response of any request
app.set('view engine', 'ejs');

// a built-in middleware function in Express.js that parses incoming requests with URL-encoded payloads
// It extracts the data sent from an HTML form (<form>) and puts it inside the req.body object
app.use(express.urlencoded({ extended: false })); // false: Uses the classic Node.js native querystring library
// Without extended: false (using querystring), req.body is undefined to server or a raw stream
// like: "username=Amit&email=amit%40gmail.com&age=25"
// Splitting Key-Value Pairs based one '&' symbol -> Splitting Keys and Values based '=' symbol ->  URL Decoding: It fixes URL-encoded special characters from %40 back into @, and spaces (+ or %20)


// NOTE: app.use means: global scope. This registers the middleware globally. Every request coming into your server will pass through this function before reaching your route handlers

// a built-in middleware function in Express.js used to serve static files like HTML, CSS, JS, img, video, etc.
app.use(express.static('public'));

// to compare and verify a cookie for its validity and activeness 
app.use(cookieParser());

// a middleware which performs some operation in between of request and response.
app.use(function (req, res, next) {
    // locals is a built-in Express object used to store data/variables that HTML view templates like EJS can access it directly.
    // scope 1. res.locals: Holds data only for a single HTTP request-response cycle. It is completely wiped clean as soon as the page finish loading
    // scope 2. res.app: Holds data for the entire life of the application across all users and pages
    res.locals.errors = [] // initialises empty array errors, means it will be empty on page load

    // try to decode incoming cookies 
    try {
        const decoded = jwt.verify(req.cookies.myApp, process.env.JWT_SECRET);
        req.user = decoded
        
    } catch(err) {
        // req.user = false
    }

    res.locals.user = req.user
    console.log(req.user);
    
    next() // must be called always, to avoid endless loading and proceed to next inlined task.
});

app.get('/', (req, res) => {
    if(req.user){
        return res.render('dashboard.ejs')
    } else{
        return res.render('homepage.ejs')
    }
});

app.get('/login', (req, res) => {
    res.render('login.ejs');
});

app.post('/register', (req, res) => {
    const errors = []

    // sanitize the user input
    req.body.username = req.body.username.trim()
    req.body.password = req.body.password.trim()

    // check for empty values
    if(!req.body.username) errors.push('Username can not be empty.')
    if(!req.body.password) errors.push('Password can not be empty.')
    
    // type check
    if(typeof req.body.username !== "string") errors.push('Username should be of STRING type.')
    if(typeof req.body.password !== "string") errors.push('Password should be of STRING type.')
    
    // if req.body.username is empty then .length will throw: .length property of something that is undefined throws a critical TypeError.
    //  -> In JS, checking a property of an object that does not exist results in undefined -> falsy value
    if(req.body.username && req.body.username.length < 3) errors.push('Username must be atleast 3 characters.') 
    if(req.body.username && req.body.username.length > 18) errors.push('Username can not be more than 18 characters.') 
    
    if(req.body.password && req.body.password.length < 4) errors.push('Password must be atleast 4 characters.') 
    if(req.body.password && req.body.password.length > 20) errors.push('Password can not be more than 20 characters.') 
    
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push('Username should contain only letters and numbers.')
    if(req.body.password && !req.body.password.match(/^[a-zA-Z0-9]+$/)) errors.push('Password should contain only letters and numbers.')

    // strict password valdation with RegExpression of criteria atleast one: a, A, 1, @, min length 8
    // if(req.body.password && !req.body.password.match(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/)) errors.push('Password criteria did not met.')

    if(errors.length){
        return res.render('homepage.ejs', { errors })
    }

    // save the new user into the db using a 'Prepared Statement'? and with encrypted password

    // password encryption
    const salt = bcrypt.genSaltSync(10) // 10 passes hashed password
    req.body.password = bcrypt.hashSync(req.body.password, salt);

    const insertStmt =  db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    const insertResult = insertStmt.run(req.body.username, req.body.password);
    
    const lookupStmt = db.prepare("SELECT * FROM users WHERE ROWID = ?");
    const userLookup = lookupStmt.get(insertResult.lastInsertRowid);
    
    // log the user IN by giving cookies
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000 ) + (60*60*24) , skyColor: "blue", userid: userLookup.id, username: userLookup.username}, process.env.JWT_SECRET);
    
    res.cookie("myApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24  // 24 hrs cookie will expire after this
        
    })
    res.send("Thank You! credentials are valid");
});

app.listen(3000);
console.log('Server running at PORT: 3000');


/*
 1. to seee the live preview within the VS code editor itself:

    -> go to ctrl + shift + P
    -> go to browser: 
        -> Open Intergrated Browser in VS code
        -> Enter the url like: http://localhost:3000

 2. too see code hierarchy and folder structure use:
    -> Ctrl + Shift + .

*/