const {Users} = require('./database/connect')

module.exports = function(app) {
    app.get('/', function (req, res) {
        res.render('pages/home')
    })
}