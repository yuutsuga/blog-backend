import express from 'express';
import morgan from 'morgan';
import 'dontenv/config';
import cors from 'cors';
import postRouter from './routes/posts';
import userRouter from './routes/user';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(morgan('dev'));
app.use(express.json());

app.use(cors());

app.use('/post', postRouter);
app.use('/user', userRouter);

app.listen(PORT, () => {
    console.log(`running on port:${PORT}`)
});