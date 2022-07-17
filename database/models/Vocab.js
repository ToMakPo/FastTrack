const mongoose = require("mongoose")

const VocabSchema = new mongoose.Schema({
    word: {
        type: String,
        trim: true,
        required: true
    },
    definition: {
        type: String,
        trim: true
    },
    useage: {
        type: String,
        trim: true
    },
    approved: {
        type: Boolean,
        required: true,
        default: false
    }
})

const Vocab = mongoose.model("vocab", VocabSchema)
module.exports = Vocab