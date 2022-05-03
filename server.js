require('dotenv').config();
const express = require('express');
const connectDB = require('./db/connect');
require('express-async-errors');
const morgan = require('morgan');
const authRouter = require('./routes/authRoutes');
const cookieParser = require('cookie-parser');


const app = express();
const port = process.env.PORT || 3000;


app.use(morgan('tiny'));
app.use(express.json());
app.use(cookieParser(process.env.JWT_KEY));

app.get('/', (req, res)=>{
    res.send('Hello world');
})

app.use('/api/v1/auth', authRouter);

const start = async()=>{
    try {
        await connectDB(process.env.MONGO_URL)
        app.listen(port, () =>
        console.log(`Server is listening on port ${port}...`)
    );
    } catch (error) {
        console.log(error);
    }
}

const currentDate = new Date();

start();
