const sendEmail = require('./sendEmail');

const sendResetPasswordEmail = async({name, lastname, email, token, origin})=>{
    const resetURL = `${origin}/user/reset-password?token=${token}&email=${email}`
    const message = `<p>Please reset password by clicking on the following link <a href="${resetURL}">Link</a></p>`

    return sendEmail({
        to:email,
        subject:'Reset password',
        html:`<h4>Hello, ${name} ${lastname}</h4>
        ${message}`
    })
};

module.exports = sendResetPasswordEmail;