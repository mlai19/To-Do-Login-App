import express from "express"
// encrypt password
import bcrypt, { hash } from 'bcryptjs'
// create an alphanumeric key that we can associate with a user to authenticate them
import jwt from 'jsonwebtoken'
// import db so can be used to hold user info in db
import db from "../db.js"
 

const router = express.Router()

// Register a new user endpoint (/auth/register)
router.post('/register', (req, res) => {
    const { username, password } = req.body

    // Encrypt the password
    const hashedPassword = bcrypt.hashSync(password, 8)

    // Save the new user and hashed password to db
    try {
        const insertUser = db.prepare(`INSERT INTO users (username, password) VALUES(?, ?)`)
        const result = insertUser.run(username, hashedPassword)

        // add default first todo
        const defaultTodo = `Hello :) Add your first todo!`
        const insertTodo = db.prepare(`INSERT INTO todos (user_id, task) VALUES (?, ?)`)
        insertTodo.run(result.lastInsertRowid, defaultTodo)

        // create a token
        const token = jwt.sign({id: result.lastInsertRowid}, process.env.JWT_SECRET, {expiresIn:'24H'})
        res.json({token})
    } catch (error) {
        console.log(err.message)
        // Status 503 means that the server is broken
        res.sendStatus(503)
    }
})

// login a user (/auth/login)
router.post('/login', (req, res) => {
    const {username, password} = req.body

    try {
        const getUser = db.prepare('SELECT * FROM users WHERE username = ?')
        const user = getUser.get(username)

        // If we cannot find a user associated with that username, return out
        if (!user){
            return res.status(404).send({message:"user not found"})}
        
        const passwordIsValid = bcrypt.compareSync(password, user.password)

        // If wrong password
        if(!passwordIsValid){
            return res.status(401).send({message: "invalid pass"})
        }

        // successful authentication
        const token = jwt.sign({id:user.id}, process.env.JWT_SECRET, {expiresIn:'24H'})

        res.json({token})

    } catch (error) {
        console.log(err.message)
        // Status 503 means that the server is broken
        res.sendStatus(503)
    }
})

export default router
