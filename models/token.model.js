const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
  token: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expires: { type: Date, required: true },
  type: { type: String, required: true },
  blacklisted: { type: Boolean, default: false },
});

module.exports = mongoose.model('Token', tokenSchema);