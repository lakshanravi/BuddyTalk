import jwt from 'jsonwebtoken';

export const generateToken = (userId, res) => {
    const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
        expiresIn: "7d"
    });

    res.cookie("jwt", token, {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true, // This is to prevent the XSS (Cross-Site Scripting) attack
        sameSite: "strict", // This is to prevent the CSRF (Cross-Site Request Forgery
        secure: process.env.NODE_ENV !== "development"

    })

    return token;
};