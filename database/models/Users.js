const mongoose = require("mongoose")
const bcrypt = require('bcrypt')
const {CHARACTERS_IN_NAMES} = require('../../global')

const MIN_USERNAME_LENGTH = 5
const MAX_USERNAME_LENGTH = 30
const MIN_PASSWORD_LENGTH = 8
const MAX_PASSWORD_LENGTH = 36
const PASSWORD_REQUIRE_LOWERCASE = true
const PASSWORD_REQUIRE_UPPERCASE = true
const PASSWORD_REQUIRE_NUMBER = true
const PASSWORD_REQUIRE_SPECIAL = true
const PASSWORD_SPECIAL_CHARACTERS = '#$@!%&*?'
const SALT_WORK_FACTOR = 10

const UserSchema = new mongoose.Schema({
    firstName: {
        type: String,
        trim: true,
        required: true
    },
    lastName: {
        type: String,
        trim: true,
        required: true
    },
    username: {
        type: String,
        trim: true,
        required: true,
        minlength: 5,
        unique: true
    },
    email: {
        type: String,
        trim: true,
        required: true,
        unique: true,
        lowercase: true
    },
    hashed: {
        type: String,
        trim: true,
        required: true
    },
    loggedIn: {
        type: Boolean,
        required: true,
        default: false
    }
    // role: {
    //     type: String,
    //     enum: ROLES
    // },
    // dateOfBirth: {
    //     type: Date
    // },
    // activity: [{
    //     category: {
    //         type: String,
    //         required: true,
    //         enum: CATEGORIES
    //     },
    //     date: {
    //         type: Date,
    //         required: true
    //     },
    //     weekOf: {
    //         type: String
    //     },
    //     problem: {
    //         type: String,
    //         required: true
    //     },
    //     expected: {
    //         type: Schema.Types.Mixed,
    //         required: true
    //     },
    //     answer: {
    //         type: Schema.Types.Mixed,
    //         required: true
    //     }
    // }]
})

/////////////////////////
/// PRIVATE FUNCTIONS ///
/////////////////////////
/** Hash and salt a password so that it can be safely stored in a database.
 * @param {String} password 
 * @returns {String} The hashed password.
 */
async function hashPassword(password) {
    return await bcrypt.hash(password, SALT_WORK_FACTOR)
}

/** Checks that the user password matched the hashed password.
 * @param {String} password 
 * @param {String} hash The hashed password that is stored in the database.
 * @returns {Boolean} 
 */
async function checkPassword(password, hash) {
    return await bcrypt.compare(password, hash)
}

////////////////////////
/// STATIC FUNCTIONS ///
////////////////////////

/// NEW USERS ///
/** Create a new user and save it to the database.
 * @param {String} firstName 
 * @param {String} lastName 
 * @param {String} username An alias that can be seen by others and is used to login.
 * @param {String} email An email that is used to login and to provide the occational updates and password resets.
 * @param {String} password The actual password. It will be hashed and salted before being saved to the database.
 * @param {String} confirm A confirmation password that should match the other password. (Optional) 
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the new profile was created.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} If successfull, then the profile that was created, else the related value that caused it to fail.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.statics.new = async function(firstName, lastName, username, email, password, confirm) {
    const validName = await this.nameValidator(firstName, lastName)
    if (!validName.passed) return validName

    const validUsername = await this.usernameValidator(username, true)
    if (!validUsername.passed) return validUsername

    const validEmail = await this.emailValidator(email, true)
    if (!validEmail.passed) return validEmail

    const validPassword = await this.passwordValidator(password, confirm)
    if (!validPassword.passed) return validPassword

    return {
        passed: true,
        field: 'insert',
        message: 'A new user was created.',
        info: await this.create({
            firstName, 
            lastName, 
            username, 
            email, 
            hashed: await hashPassword(password)
        }),
        code: 'dbusnu00'
    }
}

/// VALUE VALIDATION ///
/** Check that is name is valid.
 * @param {String} firstName The first name of the user. (optional)
 * @param {Boolean} lastName The last name of the user. (optional)
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the name is valid.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The related value that was passed in.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.statics.nameValidator = async function(firstName, lastName) {
    const PATTERN = new RegExp('^[' + CHARACTERS_IN_NAMES + ']*$', 'i')

    firstName = firstName ?? null
    if (firstName !== null) {
        if (firstName.length == 0) 
            return {passed: false, field: 'firstName', message: `No first name was provided.`, info: {firstName}, code: 'dbusnm50'}
            
        if (!PATTERN.exec(firstName))
            return {passed: false, field: 'firstName', message: `Your first name has characters that are not supported.`, info: {firstName}, code: 'dbusnm51'}
    }

    lastName = lastName ?? null
    if (firstName !== null) {
        if (lastName.length == 0) 
            return {passed: false, field: 'lastName', message: `No last name was provided.`, info: {lastName}, code: 'dbusnm52'}
        
        if (!PATTERN.exec(lastName))
            return {passed: false, field: 'lastName', message: `Your last name has characters that are not supported.`, info: {lastName}, code: 'dbusnm53'}
    }

    if (firstName === null && lastName === null)
        return {passed: false, field: 'name', message: `No name was provided.`, info: {firstName, lastName}, code: 'dbusnm54'}

    return {passed: true, field: 'name', message: 'The name is valid.', info: {firstName, lastName}, code: 'dbusnm00'}
}

/** Check that is username is valid.
 * @param {String} username 
 * @param {Boolean} checkUnique Check against the database that the username is unique.
 * @param {String} ignore When checking for unique usernames, check ignore this username.
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the username is valid.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The related value that was passed in.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.statics.usernameValidator = async function(username, checkUnique=false, ignore=null) {
    username = username.trim()
    ignore = ignore?.toLowerCase().trim() ?? null

    if (username.length < MIN_USERNAME_LENGTH) 
        return {passed: false, field: 'username', message: `The username must be at least ${MIN_USERNAME_LENGTH} characters.`, info: {username}, code: 'dbusun50'}

    if (username.length > MAX_USERNAME_LENGTH) 
        return {passed: false, field: 'username', message: `The username must be at most ${MAX_USERNAME_LENGTH} characters.`, info: {username}, code: 'dbusun51'}

    if (!/^[a-z0-9_]+$/i.exec(username))
        return {passed: false, field: 'username', message: `The username can only contain uppercase and lowercase letters, numbers, and underscores(_).`, info: {username}, code: 'dbusun52'}

    if (checkUnique && username.toLowerCase() !== ignore && await this.findOne({username: {$regex: new RegExp('^' + username + '$', 'i')}}) !== null)
        return {passed: false, field: 'username', message: 'The username is already being used by another user.', info: {username}, info: {username}, code: 'dbusun53'}
        
    return {passed: true, field: 'username', message: 'The username is valid.', info: {username}, code: 'dbusun00'}
}

/** Check that is email is valid.
 * @param {String} email 
 * @param {Boolean} checkUnique Check against the database that the username is unique.
 * @param {String} ignore When checking for unique usernames, check ignore this username.
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the email is valid.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The related value that was passed in.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.statics.emailValidator = async function(email, checkUnique=false, ignore=null) {
    email = email.toLowerCase().trim()
    if (ignore) ignore = ignore.toLowerCase().trim()
    
    const PATTERN = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/
    if (!PATTERN.exec(email)) {
        return {passed: false, field: 'email', message: `The email is not formated correctly.`, info: {email}, code: 'dbusem50'}
    }

    if (checkUnique && email.toLowerCase() !== ignore && await this.findOne({email: {$regex: new RegExp('^' + email + '$', 'i')}}) !== null)
        return {passed: false, field: 'email', message: 'An account with this email already exists.', info: {email}, code: 'dbusem51'}

    return {passed: true, field: 'email', message: 'The email is valid.', info: {email}, code: 'dbusem00'}
}

/** Check that is password is valid.
 * @param {String} password 
 * @param {String} confirm A confirmation password that should match the other password. (Optional)
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the password is valid.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The related value that was passed in.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.statics.passwordValidator = async function(password, confirm) {
    if (password.length < MIN_PASSWORD_LENGTH) 
        return {passed: false, field: 'password', message: `The password must be at least ${MIN_PASSWORD_LENGTH} characters.`, code: 'dbuspw50'}

    if (password.length > MAX_PASSWORD_LENGTH) 
        return {passed: false, field: 'password', message: `The password must be at most ${MAX_PASSWORD_LENGTH} characters.`, code: 'dbuspw51'}

    if (PASSWORD_REQUIRE_LOWERCASE && !/[a-z]/.exec(password))
        return {passed: false, field: 'password', message: `The password must contain at least one lower case letter. (a - z)`, code: 'dbuspw52'}

    if (PASSWORD_REQUIRE_UPPERCASE && !/[A-Z]/.exec(password))
        return {passed: false, field: 'password', message: `The password must contain at least one upper case letter. (A - Z)`, code: 'dbuspw53'}

    if (PASSWORD_REQUIRE_NUMBER && !/[0-1]/.exec(password))
        return {passed: false, field: 'password', message: `The password must contain at least one number. (0 - 9)`, code: 'dbuspw54'}

    const specials = new RegExp('[' + PASSWORD_SPECIAL_CHARACTERS + ']')
    if (PASSWORD_REQUIRE_SPECIAL && !specials.exec(password))
        return {passed: false, field: 'password', message: `The password must contain at least one special character. (${PASSWORD_SPECIAL_CHARACTERS})`, code: 'dbuspw55'}
    
    if (confirm != undefined && password !== confirm)
        return {passed: false, field: 'confirm', message: `The password confirmation does not match the password.`, code: 'dbuspw56'}

    return {passed: true, field: 'password', message: 'The password is valid.', code: 'dbuspw00'}
}

/// FIND RECORD ///
/** Find all records that matchs any part of the provided name.
 * @param {String} name Any part of the first and/or last name to be looked up. (case-insensitive)
 * @returns {[User]} The user profiles.
 */
UserSchema.statics.findAllByName = async function(name) {
    name = name.trim()
    const removePattern = new RegExp('[^' + CHARACTERS_IN_NAMES + ']', 'ig')
    const nameSplit = name.replaceAll(removePattern, '').split(/[\s_]/)
    const regex = { $regex: new RegExp(nameSplit.join('|'), 'i') }
    
    return await this.find(nameSplit.length > 1
        ? {firstName: regex, lastName: regex}
        : {$or: [
            {firstName: regex}, 
            {lastName: regex}
        ]}
    )
}

/** Find a record that matchs the provided username.
 * @param {String} username The full username. (case-insensitive)
 * @returns {User} The user profile or null.
 */
UserSchema.statics.findByUsername = async function(username) {
    username = username.trim()

    return await this.findOne({username: {$regex: new RegExp('^' + username + '$', 'i')}})
}

/** Find all records that matchs any part of the provided username.
 * @param {String} username Any part of the username. (case-insensitive)
 * @returns {[User]} The user profiles.
 */
UserSchema.statics.findAllByUsername = async function(username) {
    username = username.trim()

    return await this.findOne({username: {$regex: new RegExp(username, 'i')}})
}

/** Find a record that matchs the provided email.
 * @param {String} email The full email. (case-insensitive) 
 * @returns {User} The user profile or null.
 */
UserSchema.statics.findByEmail = async function(email) {
    email = email.trim()

    return await this.findOne({email: {$regex: new RegExp('^' + email + '$', 'i')}})
}

/** Find all records that matchs any part of the provided email.
 * @param {String} email Any part of the email. (case-insensitive)
 * @returns {[User]} The user profiles.
 */
UserSchema.statics.findAllByEmail = async function(email) {
    email = email.trim()

    return await this.findOne({email: {$regex: new RegExp(email, 'i')}})
}

/// ACTIONS ///
/** Log a user into the system.
 * @param {String} loginInfo The username or email to be looked up.
 * @param {String} password The password for the profile.
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the user was successfully logged in.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The user that was logged in.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.statics.login = async function(loginInfo, password) {
    loginInfo = loginInfo.trim()
    const regex = {$regex: new RegExp('^' + loginInfo + '$', 'i')}
    const user = await this.findOne({$or: [
        {username: regex}, 
        {email: regex}
    ]})

    if (!user)
        return {passed: false, field: 'login', message: 'Was not able to find that username.', info: null, code: 'dbusli50'}

    const data = await user.login(password)
    data.info = user

    return data
}

/** Log a user out of the system.
 * @param {String} loginInfo The username or email to be looked up.
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the user was successfully logged out.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The user that was logged out.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.statics.logout = async function(loginInfo) {
    loginInfo = loginInfo.trim()
    const regex = {$regex: new RegExp('^' + loginInfo + '$', 'i')}
    const user = await this.findOne({$or: [
        {username: regex}, 
        {email: regex}
    ]})

    if (!user)
        return {passed: false, field: 'logout', message: 'Was not able to find that username.', info: null, code: 'dbuslo50'}

    return user.logout(loginInfo)
}

///////////////
/// METHODS ///
///////////////

/// ACTIONS ///
/** Display the user's full name.
 * @returns {String} The full name of the user.
 */
UserSchema.methods.getDisplayName = function() {
    return `${this.firstName} ${this.lastName}`
}

/** Log the user into the system.
 * @param {String} password The password for the profile.
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the user was successfully logged in.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The user that was logged in.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.methods.login = async function(password) {
    if (!password) return {passed: false, field: 'login', message: 'No password was given.', info: null, code: 'dbusli60'}

    if (!await checkPassword(password, this.hashed)) {
        this.loggedIn = false
        return {passed: false, field: 'login', message: 'The password does not match our records.', info: null, code: 'dbusli61'}
    }

    this.loggedIn = true
    this.save()

    return {passed: true, field: 'login', message: 'Login successful', info: this, code: 'dbusli10'}
}

/** Log the user out of the system.
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the user was successfully logged out.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The user that was logged out.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.methods.logout = async function() {
    this.loggedIn = false
    this.save()

    return {passed: true, field: 'logout', message: 'Logout successful', data: this, code: 'dbuslo10'}
}

/** Change the name of the user.
 * @param {String} firstName (optional)
 * @param {String} lastName (optional)
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the name was successfully updated.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The related value that was passed in.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.methods.changeName = async function(firstName, lastName) {
    const fName = firstName !== this.firstName || firstName === undefined ? firstName : null
    const lName = lastName !== this.lastName || lastName === undefined ? lastName : null

    if (fName === null && lName === null)
        return {passed: false, field: 'name', message: 'This is the name you already have.', info: {firstName, lastName}, code: 'dbuscn50'}

    const validName = await this.model('User').nameValidator(firstName, lastName)
    if (!validName.passed) return validName

    if (fName) this.firstName = firstName
    if (lName) this.lastName = lastName
    this.save()

    return {passed: true, field: 'name', message: 'The name was updated.', info: this, code: 'dbuscn50'}
}

/** Change the username of the user.
 * @param {String} username
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the username was successfully updated.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The related value that was passed in.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.methods.changeUsername = async function(username) {
    if (username.toLowerCase().trim() === this.username.toLowerCase())
        return {passed: false, field: 'username', message: 'This is the username you already have.'}

    const validUsername = await this.model('User').usernameValidator(username, true)
    if (!validUsername.passed) return validUsername

    this.username = username
    this.save()

    return {passed: true, field: 'username', message: 'The username was updated.'}
}

/** Change the email of the user.
 * @param {String} email
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the email was successfully updated.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The related value that was passed in.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.methods.changeEmail = async function(newEmail) {
    if (this.email === newEmail.toLowerCase().trim())
        return {passed: false, field: 'email', message: 'This is the same email that is already on file.'}

    const validEmail = await this.model('User').emailValidator(newEmail, true)
    if (!validEmail.passed) return validEmail

    this.email = newEmail
    this.save()

    return {passed: true, field: 'email', message: 'The email was updated.'}
}

/** Change the password of the user.
 * @param {String} password The actual password. It will be hashed and salted before being saved to the database.
 * @param {String} confirm A confirmation password that should match the other password. (Optional) 
 * @returns {Object} An object with the following values:
 *  - passed {Boolean} Indicates if the password was successfully updated.
 *  - field {String} The field that this value is connected to.
 *  - message {String} The message being sent back.
 *  - info {Object} The related value that was passed in.
 *  - code {String} A unique identifier that specifically references this message.
 */
UserSchema.methods.changePassword = async function(password, confirm) {
    const validPassword = await this.model('User').passwordValidator(password, confirm)
    if (!validPassword.passed) return validPassword

    this.hashed = await hashPassword(password)
    this.save()

    return {passed: true, field: 'password', message: 'The password was updated.'}
}

/////////////////////
/// API FUNCTIONS ///
/////////////////////
/** Pass any of the following filters to get a list of matching records.
 * @param {Object} filters All values are optional and case-insensitive. Providing nothing 
 *      will return all records. The id and hashed password are not sent back.
 *  - id        - The id for the record. This will return only one record.
 *  - name      - any part of the first and/or last name.
 *  - firstName - any part of specificly the first name.
 *  - lastName  - any part of specificly the last name.
 *  - username  - any part of the username.
 *  - email     - any part of the email.
 *  - loggedIn  - true for all users that are logged in and false for all users not logged in.
 * @returns 
 */
UserSchema.statics.api = async function(filters={}) {
    const selects = '-_id -__v -hashed'
    if (filters.hasOwnProperty('id')) {
        return await User.findById(filters.id).select(selects)
    }

    const match = {}
    const removePattern = new RegExp('[^' + CHARACTERS_IN_NAMES + ']', 'ig')
    const namePattern = name => { return {$regex: new RegExp(name.replaceAll(removePattern, '').split(/[\s_]/).join('|'), 'i')} }

    if (filters.hasOwnProperty('name')) {
        const name = filters.name.trim()
        const nameSplit = name.replaceAll(removePattern, '').split(/[\s_]/)
        const regex = namePattern(name)

        if (nameSplit.length > 1) {
            match.firstName = regex
            match.lastName = regex
        } else {
            match['$or'] = [
                {firstName: regex}, 
                {lastName: regex}
            ]
        }
    }

    Object.keys(filters).forEach(k => {
        if (k === 'hashed') return

        const value = filters[k]
        if (typeof value === 'boolean') {
            match[k] = value
        } else
        if (!['id', 'name'].includes(k)) {
            match[k] = {$regex: new RegExp(value, 'i')}
        }
    }) // Making all filters case-insensitive.
    
    return await User.find(match).select(selects)
}

const User = mongoose.model("user", UserSchema)
module.exports = User