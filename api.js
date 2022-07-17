const {Users} = require('./database/connect')

module.exports = function(app) {
    app.get('/api/users', async function (req, res) {
        const users = await Users.find({})
        
        res.json(users)
    })
}