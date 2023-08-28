const nodemailer = require("nodemailer");

const sendMail = async (options) => {
    const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        auth:{
            user: 'muhammadahmadrcs@gmail.com',
            pass: 'lgjlntamfebjdkbz',
        },
    });
    const mailOptions = {
        from: 'muhammadahmadrcs@gmail.com',
        to: options.email,
        subject: options.subject,
        text: options.message,
    };
    await transporter.sendMail(mailOptions);
};

module.exports = sendMail;