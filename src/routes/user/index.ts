import { Router, RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import 'dotenv/config';
import prisma from '../../database';

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

// sign up user
router.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    const infoNeeded = name || email || password;

    if (!infoNeeded) {
        return res.status(401).send('please fill in all fields.');
    }

    const user = await prisma.user.findFirst({
        where: {
            email
        },
        select: {
            email: true
        }
    });

    if (user) {
        return res.status(400).send('this email is already in use');
    }

    const newUser = await prisma.user.create({
        data: {
            name,
            email,
            password: bcrypt.hashSync(password, 10)
        },
        select: {
            id: true,
            name: true,
            email: true
        }
    });

    const token = jwt.sign({id: newUser.id}, SECRET, {
        expiresIn: '3h'
    });

    res.status(200).send({ newUser, token });
});

// sign in user
router.post('/signin', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(401).send('please fill in all fields.');
    }

    const user = await prisma.user.findFirst({
        where: {
            email
        },
        select: {
            id: true,
            name: true,
            email: true,
            password: true
        }
    });

    if (!user) {
        return res.status(401).send('you are not registered.');
    }

    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).send('passwords do not match.');
    }

    const token = jwt.sign({ id: user.id}, SECRET, {
        expiresIn: '2h'
    });

    res.status(200).send({ user, token });
});

// get users 
router.get('/', loggedMiddleware, async (req, res) => {
    const users = await prisma.user.findMany({ });

    res.status(200).send({ users });
});

// get user by id
router.get('/:id', loggedMiddleware, async (req, res) => {
    const { id } = req.params;

    const user = await prisma.user.findFirst({
        where: {
            id
        },
        select: {
            name: true
        }
    });

    res.status(200).send({ user });
});

// update user info
router.put('/update', loggedMiddleware, async (req, res) => {
    const { userId } = res.locals;
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(401).send('please fill in all fields');
    }
    
    const newUser = await prisma.user.updateMany({
        where: {
            id: userId
        },
        data: {
            name,
            email,
            password
        }
    });

    res.status(200).send({ newUser });
});

// delete user 
router.delete('/delete', loggedMiddleware, async (req, res) => {
    const { userId } = res.locals;

    const deletedUser = await prisma.user.deleteMany({
        where: {
            id: userId
        }
    });

    if (!deletedUser.count) {
        return res.status(404).send({ deleted: false });
    }

    res.status(200).send({ deleted: true });
});

export default router;
