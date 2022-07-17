require('dotenv').config()
const express = require('express')
const PORT = process.env.PORT || 3000

/// EXPRESS ///
const app = express()
app.use(express.static('public'))
app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.set("view engine", "ejs");

/// ROUTES ///
require('./routes')(app)
require('./api')(app)

/// START SERVER ///
const server = app.listen(PORT, () => {
    console.info(`App running on http://localhost:${PORT}`)
})