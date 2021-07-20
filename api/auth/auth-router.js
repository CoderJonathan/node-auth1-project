// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')

const router = require('express').Router()
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
} = require('./auth-middleware')

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
  router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {
    const {username, password} = req.body
    const hash = bcrypt.hashSync(password, 10)
  
    Users.add({username, password: hash})
    .then(user => {
      res.status(201).json(user)
    })
    .catch(next)
  })

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
  router.post('/login', checkUsernameExists, (req, res, next) => {
    const {username} = req.body

  Users.findIdAndUser({username})
    .then(([user]) => {
      req.session.user = user
      res.json({
        message: `welcome ${user.username}`
      })
    })
    .catch(err => {
      next(err)
    })
  
  })
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
  router.get('/logout', (req, res, next) => {
    if (req.session.user) {
      res.clearCookie('chocolatechip')
      req.session.destroy(err =>{
        if (err) {
            res.json({
              message: `you can never escape`
            })
        } else {
            res.json({
              message: `logged out`
            })
          }
      })
    } else {
        res.json({
          message: `no session`
        })
    }
  })

  router.use((err, req, res, next) => { // eslint-disable-line
    res.status(err.status || 500).json({
      customMessage: `Authorization acting wierd`,
      message: err.message,
      stack: err.stack,
    })
  })
// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router