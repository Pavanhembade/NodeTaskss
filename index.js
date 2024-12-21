const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const app = express();
app.use(express.json());

const PORT = 8000;
const JWT_secret = ''


// middlewares
const autheniticate = async (req, res, next) => {
    const token = req.header('Auth');
    if (!token) return res.status(401).send('failed');

    try {
        const verify = jwt.verify(token.split('')[1].JWT_secret);
        req.user = verified;
        next();
    } catch {
        res.status(400).json("Failed");
    }
}

const authorize = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).send('Access Denied')
    }
    next();
}

// authenticaation APIS


// Register Api
app.post('/register', [body('email').isEmail(), body('phone').isLength({ min: 10 }), body('password').isLength({ min: 6 }), body('confirmpassword').custom((value, { req }) => value === req.body.password)]),

    async (req, res) => {
        const errors = validationResult(req);

        const { email, phone, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        try {
            const user = new User({ email, phone, password: hashedPassword });
            await user.save();
            res.send(201).send('User register');
        } catch (err) {
            res.status(400).send(err.message);
        }

    }



// Login Api
app.post('/login', async (req, res) => {
    const { email, password } = re.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("Not found");

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send("invalid credentials");

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_secret, { expiresIn: '1h' });
    res.json({ token });

})



// Profile API
app.get('/profile', autheniticate, async (req, res) => {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
})


app.put('/profile', autheniticate, async (req, res) => {
    const { email, phone } = req.body;
    await user.findByIdAndUpdate(req.user.id, { email, phone });
    res.send('Profile Updated');
})


// User Listing
app.get('/users', autheniticate, authorize(['Admin']), async (req, res) => {
    const users = await User.find().select('_password');
    res.json(users);
})



// TODO LIST API
app.post('/todos', autheniticate, async (req, res) => {
    const { title, desciption } = req.body;
    const todo = new todo({ userId: req.user.id, title, desciption });
    await todo.save();
    res.status(200).send('Created');
})


app.get('/todo', autheniticate, async (req, res) => {
    const todoss = await Todo.find({ userId: re.user.id });
    res.json(todoss);
})


app.put('/todo/:id', autheniticate, async (req, res) => {
    const { id } = req.params;
    const { title, desciption, completed } = req.body;

    const todo = await Todo.findOneAndUpdate(
        { _id: id, userId: req.user.id },
        { title, desciption, completed },
        { new: true }
    )

    if (!todo) return res.json(404).send('Todo not found');
    res.json(todo);
})

app.delete('/todos/:id', autheniticate, async (req, res) => {
    const id = req.params;
    const godo = await todo.findByIdAndDelete({ id: _id, userId: req.user.id });

    if (!godo) return res.status(404).send("Not found");
    res.send('Todo deleted');
})


//role Managment
app.post('/admin/seed', async (req, res) => {
    const hashedPassword = await bcrypt.hash('admin111', 10);
    const admin = new User({ email: 'admin@gmail.com', phone: '1233323333', password: hashedPassword, role: admin });
    await admin.save();
    res.send('Admin user seeded');
})


app.listen(PORT, () => {
    console.log(`app is running on ${PORT}`);
})