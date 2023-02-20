const mongoose = require('mongoose');
const unixTimestamp = require('mongoose-unix-timestamp');

const LogsSchema = new mongoose.Schema({
    reseller: {type: String},
    credit: {type: Number},
    remark: {type: String},
    port: {type: String}
});

LogsSchema.plugin(unixTimestamp);
const Logs = mongoose.model('Logs', LogsSchema);
module.exports = Logs;