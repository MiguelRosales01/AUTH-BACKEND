const User = require('../models/User');
const { StatusCodes } = require('http-status-codes');
const crypto = require('crypto');
const sendVerificationEmail = require('../utils/sendVerificationEmail');
const Token = require('../models/Token');
const createTokenUser = require('../utils/createTokenUser');
const {attachCookiesToResponse} = require('../utils/jwt');
const sendResetPasswordEmail = require('../utils/sendResetPasswordEmail');



const register = async (req, res)=>{
    const {name, lastname, email, password} = req.body;

    const emailAlreadyExists = await User.findOne({email});

    if(emailAlreadyExists){
        return res.status(StatusCodes.UNAUTHORIZED).json('Email already exists');
    }

    const verificationToken = crypto.randomBytes(40).toString('hex');

    const user = await User.create({
        name, lastname, email, password, verificationToken
    });

    const origin = 'http://localhost:3000';

    await sendVerificationEmail({name:user.name, email:user.email, verificationToken:user.verificationToken, origin});

    return res.status(StatusCodes.CREATED).json({user});

};

const verifyEmail = async (req, res)=>{
    const {verificationToken, email} = req.body;

    const user = await User.findOne({email});

    if(!user){
        return res.status(StatusCodes.NOT_FOUND).json('Verification failed, no user found with that email')
    }

    if(user.verificationToken !== verificationToken){
        return res.status(StatusCodes.UNAUTHORIZED).json('Verification failed');
    }

    (user.isVerified = true), (user.verified = Date.now());
    user.verificationToken = '';

    await user.save();

    res.status(StatusCodes.OK).json({ msg: 'Email Verified' });
}

const login = async (req, res)=>{
    const {email, password} = req.body;

    if(!email || !password){
        return res.status(StatusCodes.UNAUTHORIZED).json('Please provide the credentials');
    }

    const user = await User.findOne({email});

    if(!user){
        return res.status(StatusCodes.NOT_FOUND).json('No user found with that email')
    }

    const isPasswordCorrect = await user.comparePassword(password);

    if (!isPasswordCorrect) {
        return res.status(StatusCodes.NOT_FOUND).json('Wrong password');
    }

    if(!user.isVerified){
        return res.status(StatusCodes.UNAUTHORIZED).json('Please verify your email');
    }

    const tokenUser = createTokenUser(user);

    let refreshToken = '';

    const existingToken = await Token.findOne({user:user._id});

    if(existingToken){
        const {isValid} = existingToken;
        if(!isValid){
            return res.status(StatusCodes.UNAUTHORIZED).json('Invalid credentials')
        };
        refreshToken = existingToken.refreshToken;
        attachCookiesToResponse({ res, user: tokenUser, refreshToken });

        res.status(StatusCodes.OK).json({ user: tokenUser});
        return;
    };

    refreshToken = crypto.randomBytes(40).toString('hex');
    const userAgent = req.headers['user-agent'];
    const ip = req.ip;

    const userToken = {refreshToken, userAgent, ip, user:user._id};

    await Token.create(userToken);

    attachCookiesToResponse({ res, user: tokenUser, refreshToken });

    res.status(StatusCodes.OK).json({ user: tokenUser});
};

const logout = async (req, res)=>{

    await Token.findOneAndDelete({user: req.user.userId});

    res.cookie('accessToken', 'logout',{
        httpOnly: true,
        expires: new Date(Date.now()),
    });
    res.cookie('refreshToken', 'logout',{
        httpOnly: true,
        expires: new Date(Date.now()),
    });

    return res.status(StatusCodes.OK).json('User has logged out');
};

const forgotPassword = async(req, res)=>{
    const {email} = req.body;
    if(!email){
        return res.status(StatusCodes.UNAUTHORIZED).json('Please provide an email');
    };

    const user = await User.findOne({email});

    if(user){

        const passwordToken = crypto.randomBytes(70).toString('hex');

        const origin = 'http://localhost:3000';
        await sendResetPasswordEmail({name:user.name, lastname: user.lastname, email: user.email, token: passwordToken, origin});

        const tenMinutes = 1000 * 60 * 10;

        const passwordTokenExpirationDate= new Date(Date.now() + tenMinutes)

        user.passwordToken = passwordToken;
        user.passwordTokenExpirationDate = passwordTokenExpirationDate;
        await user.save();
    };

    res.status(StatusCodes.OK).json('Please check your email to reset the password');
}

const resetPassword = async(req, res)=>{
    const {token, email, password} = req.body;

    if(!token || !email || !password){
        return res.status(StatusCodes.UNAUTHORIZED).json('Please provide the credentials')
    }

    const user = await User.findOne({email});

    if(user){
        const currentDate = new Date();
        if(user.passwordToken === token && user.passwordTokenExpirationDate > currentDate){
            user.password = password;
            user.passwordToken = null;
            user.passwordTokenExpirationDate = null;
            await user.save();
        }
    }
}


module.exports = {
    register,
    login,
    logout,
    verifyEmail, 
    forgotPassword, 
    resetPassword
}