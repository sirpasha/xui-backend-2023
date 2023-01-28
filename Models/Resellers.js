const mongoose = require('mongoose');
const unixTimestamp = require('mongoose-unix-timestamp');

const ResellersSchema = new mongoose.Schema({
    username: {type: String, unique: true, require: true},
    password: {type: String},
    credit: {type: Number, default: 0},
    prefix: {type: String, unique: true}
});

ResellersSchema.plugin(unixTimestamp);
const Resellers = mongoose.model('Resellers', ResellersSchema);
module.exports = Resellers;