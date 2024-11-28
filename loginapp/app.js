import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import fs from 'fs';
import path from 'path';

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = 'your_secret_key';
const USERS_FILE = path.join(process.cwd(), 'users.json');

// doc ghi file ng dung
const readUsersFromFile = () => {
    try {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const writeUsersToFile = (users) => {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

// dang ky
app.post('/signup', async (req, res) => {
    const { email, password, name } = req.body;
    const users = readUsersFromFile();

    if (users[email]) {
        return res.status(400).json({ message: "Email đã tồn tại" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users[email] = { password: hashedPassword, name };

    writeUsersToFile(users);
    res.json({ message: "Tài khoản đã được tạo thành công" });
});

// dang nhap
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const users = readUsersFromFile();

    // kt email
    const user = users[email];
    if (!user) {
        return res.status(404).json({ message: "Email không tồn tại" });
    }

    // kt mk
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).json({ message: "Sai mật khẩu" });
    }

    // access token
    const token = jwt.sign({ email: email }, SECRET_KEY, { expiresIn: '30m' });
    return res.json({ access_token: token });
});

const PORT = 7000;
app.get('/', (req, res) => {
    res.send("Server is running!");
});
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
