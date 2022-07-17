require('dotenv').config()
const mongoose = require('mongoose')
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/fasttrack'

console.log('CONNECTING TO MONGODB')

mongoose.connection.on('connected', () => console.info('MongoDB has connected successfully'))
mongoose.connection.on('disconnected', () => console.info('MongoDB has disconnected successfully'))
mongoose.connection.on('error', err => console.error('MongoDB was unable to connected:', err))

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})

console.log('CONNECTED TO MONGODB')

module.exports = require('./models')