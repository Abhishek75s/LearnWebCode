import express from 'express';

const app = express();

app.set('view engine', 'ejs');
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.render('homepage.ejs')
});

app.get('/login', (req, res) => {
    res.render('login.ejs');
});

app.listen(3000);
console.log('Server running at PORT: 3000');


/*
to seee the live preview within the VS code editor itself:

    -> go to ctrl + shift + P
    -> go to browser: 
        -> Open Intergrated Browser in VS code
        -> Enter the url like: http://localhost:3000

*/