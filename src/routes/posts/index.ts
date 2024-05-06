import { Router, RequestHandler } from 'express';
import prisma from '../../database';
import jwt from 'jsonwebtoken';
import 'dotenv/config';

const router = Router();
const SECRET: string = process.env.SECRET as string;

const loggedMiddleware: RequestHandler = (req, res, next) => {
    const auth = req.headers.authorization || '';

    const parts = auth.split(' ');

    if(parts.length != 2)
        return res.status(401).send();

    const [prefix, token] = parts;

    if(prefix !== 'Bearer')
        return res.status(401).send();

    jwt.verify(token, SECRET, (error, decoded) => {
        if(error) {
            return res.status(401).send(error);
        }

        res.locals.userId = (decoded as jwt.JwtPayload).id;

        next();
    });
};

// route to get all posts
router.get('/', async (req, res) => {
    res.status(200).send({
        result: await prisma.post.findMany({
            where: { },
            select: {
                id: true,
                title: true,
                content: true
            }
        })
    });
});

// route to get a post by id
router.get('/:id', async (req, res) => {
    const { id } = req.params;

    const post = await prisma.post.findFirst({
        where: {
            id
        }
    });

    if (!post) {
        return res.status(404).send('there are no posts.');
    }

    res.status(200).send({ post });
});

// route to create a post
router.post('/create', loggedMiddleware, async (req, res) => {
    const { title, content } = req.body;
    const { userId } = res.locals;

    if (!title || !content) {
        return res.status(401).send('please fill in all fields.')
    }

    const newPost = await prisma.post.create({
        data: {
            userId,
            title,
            content
        }
    });

    res.status(200).send({ newPost });
});

// route to update a post
router.put('/update', loggedMiddleware, async (req, res) => {
    const { id, title, content } = req.body;
    const { userId } = res.locals;

    if (!id || !title || !content) {
        return res.status(401).send('please fill in all fields.');
    }

    const updatePost = await prisma.post.updateMany({
        where: {
            id,
            userId
        },
        data: {
            title,
            content,
            updated: true
        }
    });

    if (!updatePost.count) {
        return res.status(404).send({ updated: false });
    } 

    res.status(200).send({ updated: true, updatePost });
});

// route to delete a post 
router.delete('/delete', loggedMiddleware, async (req, res) => {
    const { id } = req.body;
    const { userId } = res.locals;

    const deletedPost = await prisma.post.deleteMany({
        where: {
            id,
            userId
        }
    });

    if (!deletedPost.count) {
        return res.status(404).send({ deleted: false });
    }

    res.status(200).send({ deleted: true });
});

export default router;
