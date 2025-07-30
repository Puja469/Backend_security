
const mongoose = require('mongoose');
const credSchema =new mongoose.Schema({
    email : {type: String,required:true },
    password : {type: String,required:true,} ,
    role : {type: String,required:true,},
    fname: { type: String, required: true },

});

const Cred = mongoose.model('Creds',credSchema);

module.exports = Cred;