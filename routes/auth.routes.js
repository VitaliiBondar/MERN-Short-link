const {Router} = require('express');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const {check, validationResult} = require('express-validator');
const User = require('../models/User');
const router = Router();

// /api/auth/register
router.post('/register',[
    check('email', 'Your email is not valid').isEmail(),
    check('password', 'min password length 6 symbols').isLength({min:6})
], async (req, res)=>{
    try{
        console.log('Body', req.body);
        const errors = validationResult(req);
        if (!errors.isEmpty()){
            return res.status(400).json({
                errors:errors.array(),
                message:'Wrong data'
            })
        }
        const {email, password} = req.body;
        const candidate = await User.findOne({email});
        if(candidate) {
            return res.status(400).json({message: 'You cannot use this email'})
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({email, password: hashedPassword})

        await user.save()

        res.status(201).json({message: 'User created'})
    } catch (e) {
        res.status(500).json({message: 'Something is wrong, try later'})
    }
});

// /api/auth/login
router.post('/login', [
    check('email', 'Your email is not valid').normalizeEmail().isEmail(),
    check('password', 'Enter your password').exists()
], async (req, res)=>{
    try{
        const errors = validationResult(req);
        if (!errors.isEmpty()){
            return res.status(400).json({
                errors:errors.array(),
                message:'Wrong data'
            })
        }
        const {email, password} = req.body;
        const user = await User.findOne({email});
        if(!user) {
            return res.status(400).json({message: 'User not founded'})
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if (!isMatch){
            return res.status(400).json({message: 'Wrong password'})
        }
        const token = jwt.sign(
            {userId: user.id},
            config.get('jwtSecret'),
            {expiresIn: '1h'}
        )

        res.json({token, userId:user.id})

    } catch (e) {
        res.status(500).json({message: 'Something is wrong, try later'})
    }
});

module.exports = router;