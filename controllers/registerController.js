const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const conn = require('../dbConnection').promise();

exports.register = async (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    try {
        // Проверка на существующий email
        const [rows] = await conn.execute(
            "SELECT email FROM users WHERE email=?",
            [req.body.email]
        );

        if (rows.length > 0) {
            return res.status(409).json({
                message: "The E-mail is already in use",
            });
        }

        // Хеширование пароля
        const hashPass = await bcrypt.hash(req.body.password, 12);

        // Вставка нового пользователя в базу данных
        await conn.execute('INSERT INTO users(name, email, password) VALUES(?, ?, ?)', [
            req.body.name,
            req.body.email,
            hashPass
        ]);

        // Возврат успешного ответа
        return res.status(201).json({
            message: "User registered successfully",
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            message: "An error occurred while registering the user.",
        });
    }
};
