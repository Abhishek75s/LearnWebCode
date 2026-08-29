import express from 'express';
import Database from "better-sqlite3";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import "dotenv/config";
import cookieParser from 'cookie-parser';
import sanitizeHTML from 'sanitize-html';

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

    db.prepare(`
        CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        authorid INTEGER,
        username STRING NOT NULL, 
        FOREIGN KEY (authorid) REFERENCES users (id)
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

// a middleware, which performs some operation in between of request and response.
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
        req.user = false
    }

    res.locals.user = req.user  // ejs template can access this value
    // console.log(req.user); // print the  user details if Logged IN 
    
    next() // must be called always, to avoid endless loading and proceed to next inlined task.
});

app.get('/', (req, res) => {
    if(req.user){
        const fetchAllPostsStmt = db.prepare('SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC')
        const myAllPosts = fetchAllPostsStmt.all(req.user.userid) // all method fetches all the matching rows from the DB while get is used to fetch single record

        //  db.all() -> It always returns an Array of objects, if nothing matches return [] empty array.
        //  db.get() -> It returns a single Object. If no row matches, it returns undefined.

        return res.render('dashboard.ejs', { posts: myAllPosts})
    } else {
        return res.render('login.ejs')
    }
});

app.get('/login', (req, res) => {
    res.render('login.ejs');
});

app.get('/sign-up', (req, res) => {
    res.render('sign-up.ejs');
});

app.post('/login', (req, res) => {
    let errors = [];

    // type check
    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.password !== "string") req.body.password = ""

    // check for empty values
    if(!req.body.username.trim()) errors = ['Username can not be empty.']
    if(!req.body.password) errors = ['Password can not be empty.']

    if(errors.length) {
        return res.render('login', { errors });
    }

    const findUserStmt = db.prepare("SELECT * FROM users WHERE USERNAME = ?");
    const userFound = findUserStmt.get(req.body.username.trim())

    if(!userFound) {
        errors = ["User not Found!"];
        return res.render('login', { errors });
    }

    const passwordMatched = bcrypt.compareSync(req.body.password, userFound.password)

    if(!passwordMatched) {
        errors = ["Invalid password!"];
        return res.render('login', { errors });
    }
    
    // log the user IN by giving a cookie
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000 ) + (60*60*24) , skyColor: "blue", userid: userFound.id, username: userFound.username}, process.env.JWT_SECRET);
    
    res.cookie("myApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24  // 24 hrs cookie will expire after this
        
    })
    res.redirect('/');
    
});

app.get('/logout', (req, res) => {
    res.clearCookie(('myApp'))
    res.redirect('/login')
    res.send('okay')
});

app.get('/create-post', LoggedInCheck, (req, res) => {
    res.render('create-post.ejs');
});

function LoggedInCheck(req, res, next) {
    if(req.user) {
        return next();
    }
    res.redirect('/');
    res.send("OK")
    next();
}

function commonPostValidation(req) {
    const errors = []

    if(typeof req.body.title !== 'string') req.body.title = ''
    if(typeof req.body.body !== 'string') req.body.body = ''
    
    // sanitize HTML 
    req.body.title = sanitizeHTML(req.body.title.trim(), { allowedTags: [], allowedAttributes: {} })
    req.body.body = sanitizeHTML(req.body.body.trim(), { allowedTags: [], allowedAttributes: {} })

    if(!req.body.title) errors.push('You must provide a Title for your Post!')
    if(!req.body.body) errors.push('You must provide Content for your Post!')

    return errors;
}

app.get('/edit-post/:id', (req, res) => {
    // try to lookup the post in question
    const postLookupStmt = db.prepare('SELECT * FROM posts WHERE posts.id = ?')
    const post = postLookupStmt.get(req.params.id)

    if(!post) {
        return res.redirect('/')
    }

    // check only post author has access to edit it
    if(post.authorid !== req.user.userid) {
        res.redirect('/')
    }
    
    // render edit post template if post is FOUND
    res.render('edit-post', { post })    // no { post: post } used here
});

app.post('/edit-post/:id', (req, res) => {
    // try to lookup the post in question
    const postLookupStmt = db.prepare('SELECT * FROM posts WHERE posts.id = ?')
    const post = postLookupStmt.get(req.params.id)

    if(!post) {
        return res.redirect('/')
    }

    // check only post author has access to edit it
    if(post.authorid !== req.user.userid) {
        res.redirect('/')
    }

    const errors = commonPostValidation(req);

    if(errors.length !== 0) {
        return res.render('edit-post', { errros })
    }

    const updatePostStmt = db.prepare('UPDATE posts SET title = ?, body = ? WHERE id = ?')
    updatePostStmt.run(req.body.title, req.body.body, req.params.id)

    res.redirect(`/post/${req.params.id}`)
});

app.post('/delete-post/:id', (req, res) => {
    // try to lookup the post in question
    const postLookupStmt = db.prepare('SELECT * FROM posts WHERE posts.id = ?')
    const post = postLookupStmt.get(req.params.id)

    if(!post) {
        return res.redirect('/')
    }

    // check only post author has access to edit it
    if(post.authorid !== req.user.userid) {
        res.redirect('/')
    }

    const deletePostStmt = db.prepare('DELETE FROM posts WHERE id = ?')
    deletePostStmt.run(req.params.id)

    res.redirect('/')
});

app.get('/post/:id', LoggedInCheck, (req, res) => {
    // const fetchPostStmt = db.prepare('SELECT * FROM posts WHERE id = ?')

    // extract data from different tables using DB JOINS
    const fetchPostStmt = db.prepare('SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?')
    const getPost = fetchPostStmt.get(req.params.id)

    if(!getPost) {
        return res.redirect('/')
    }

    res.render('view-post.ejs', { post: getPost}) // in modern JS only { post } is also fine instead of { post: post }, because key name and value name is same
});

app.post('/create-post', LoggedInCheck, (req, res) => {
    const errors = commonPostValidation(req);
    // console.log(req.user);
    if(errors.length){
        return res.render('create-post.ejs', {errors})
    }

    // save new post to DB
    const newPostStmt = db.prepare('INSERT INTO posts (title, body, authorid, username, createdDate) VALUES (?, ?, ?, ?, ?)')
    const result = newPostStmt.run(req.body.title, req.body.body, req.user.userid, req.user.username, new Date().toISOString())

    const getPostDB = db.prepare('SELECT * FROM posts WHERE ROWID = ?')
    const savedPost = getPostDB.get(result.lastInsertRowid)

    // console.log(savedPost);

    res.redirect(`/post/${savedPost.id}`)
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

    // check if username already EXISTS
    const usernameStmt = db.prepare("SELECT * FROM users WHERE username = ?");
    const userFound = usernameStmt.get(req.body.username.trim());
    if(userFound) {
        errors.push('Username already exists!')
        
        if(errors.length){
        return res.render('sign-up.ejs', { errors })
    }
    }
    
    if(req.body.password && req.body.password.length < 4) errors.push('Password must be atleast 4 characters.') 
    if(req.body.password && req.body.password.length > 20) errors.push('Password can not be more than 20 characters.') 
    
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push('Username should contain only letters and numbers.')
    if(req.body.password && !req.body.password.match(/^[a-zA-Z0-9]+$/)) errors.push('Password should contain only letters and numbers.')

    // strict password valdation with RegExpression of criteria atleast one: a, A, 1, @, min length 8
    // if(req.body.password && !req.body.password.match(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/)) errors.push('Password criteria did not met.')

    if(errors.length){
        return res.render('sign-up.ejs', { errors })
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
    res.redirect('/');
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