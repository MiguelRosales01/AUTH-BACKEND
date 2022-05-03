const nodemailer = require('nodemailer');
const nodemailerConfig = require('./nodemailerConfig');

const sendEmail = async ({to, subject, html})=>{

    const testAccount = await nodemailer.createTestAccount();

    const transporter = nodemailer.createTransport(nodemailerConfig);
    const info = await transporter.sendMail({
        from: '"Zelma Haag 👻" zelma.haag42@ethereal.email', // sender address
        to, 
        subject,
        html,
      });
}

module.exports = sendEmail;