const express = require('express');
const bcrypt = require('bcryptjs');
const Users = require('../user/user-model');
const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets')
const router = express.Router();

router.post("/register", async (req, res, next) => {
	try {
		const { username } = req.body
		const user = await Users.findBy({ username }).first()
        //When they try to register check if the username is taken.
		if (user) {
			return res.status(409).json({
				message: "Username is already taken",
			})
		}
        //add the user with a hashed password to the database
		res.status(201).json(await Users.add(req.body))
	} catch(err) {
		next(err)
	}
})

router.post("/login", async (req, res, next) => {
    try {
        const {username, password} = req.body;

        const user =  await Users.findBy({username}).first()

        //since bcrypt hashes generate different results due to salting
        //we rely on bcrpyt magic internals to compare hashes
        //rather than doing it manaully with !==
        const passwordValid = await bcrypt.compare(password, user.password)

        if(!user || !passwordValid) {
            return res.status(401).json({
                message: "INVALID CREDENTIALS"
            })
        }
        req.session.user = user;
        const token = generateToken(user)
        res.status(200).json({message: "Welcome user", token})

    }catch(err) {
        next(err);
    }
})
//Assume the token can be seen by anyone and dont send sensitive data.
function generateToken(user) {
    const payload = {
        subject:user.id, //Who is this about
        username: user.username
    }
    
    const options = {
        expiresIn: '1h'//this is an option provided by the jwt library.
    }
    return jwt.sign(payload, secrets.jwtSecret, options)
}


router.get('/logout', (req, res) => {
    if(req.session) {
        req.session.destroy(err => {
            if(err) {
                res.json({message: "We're sorry, but an error has occurred"})
            }else {
                res.status(200).json({message: 'You have been logged out!'})
            }
        })
    }else {
        res.status(200).json({message: "You weren't even logged in, dude."})
    }
})

module.exports = router;