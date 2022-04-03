const express = require('express')
const User = require('../models/user')
const auth = require('../middleware/auth')
const jwt = require('jsonwebtoken')
const router = new express.Router()

router.post('/users/signup', async (req, res) => {
    const user = new User(req.body)

    try {
        await user.save()
        const access_token = await user.generateAccessToken()
        const refresh_token = await user.generateRefreshToken()
        res.status(201).send({ user, access_token,refresh_token })
    } catch (e) {
        res.status(400).send(e)
    }
})

router.post('/users/login', async (req, res) => {
    try {
        const user = await User.findByCredentials(req.body.email, req.body.password)
       const access_token = await user.generateAccessToken()
        const refresh_token = await user.generateRefreshToken()
        res.send({ user, access_token,refresh_token })
    } catch (e) {
        res.status(400).send()
    }
})

router.post('/users/refresh', async (req, res) => {
  
        const token = req.body.refresh_token; 
         console.log(req.body.refresh_token)
         if (!token)
         return res.status(401).json("You are not authenticated!");
         const decoded = jwt.verify(token, 'refreshTokenSecret')
         const user = await User.findOne({ _id: decoded._id, 'r_tokens.refresh_token': token })
         const access_token = await user.generateAccessToken()
         const refresh_token  = await user.generateRefreshToken()
         user.a_tokens = user.a_tokens.concat({access_token })
         user.r_tokens  = user.r_tokens.concat({refresh_token})
         
         res.send({ user, access_token,refresh_token })
    }
)


router.post('/users/logout', auth,  (req, res) => {
   
        const refreshToken = req.body.refresh_token;
        console.log(refreshToken)
        console.log("User is " ,req.user)
       req.user.r_tokens = req.user.r_tokens.filter((token1) => token1 !== refreshToken);
        res.status(200).json("You logged out successfully.");
      });
  
router.post('/users/logoutAll', auth, async (req, res) => {
    try {
        req.user.a_tokens = []
        req.user.r_tokens =[]
        await req.user.save()
        res.send()
    } catch (e) {
        res.status(500).send()
    }
})

router.get('/users/me', auth, async (req, res) => {
    res.send(req.user)
})

router.patch('/users/me', auth, async (req, res) => {
    const updates = Object.keys(req.body)
    const allowedUpdates = ['name', 'email', 'password', 'age']
    const isValidOperation = updates.every((update) => allowedUpdates.includes(update))

    if (!isValidOperation) {
        return res.status(400).send({ error: 'Invalid updates!' })
    }

    try {
        updates.forEach((update) => req.user[update] = req.body[update])
        await req.user.save()
        res.send(req.user)
    } catch (e) {
        res.status(400).send(e)
    }
})

router.delete('/users/me', auth, async (req, res) => {
    try {
        await req.user.remove()
        res.send(req.user)
    } catch (e) {
        res.status(500).send()
    }
})

module.exports = router