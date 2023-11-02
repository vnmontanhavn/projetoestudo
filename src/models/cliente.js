const mongoose = require("../database/conexao")

const schema = new mongoose.Schema({
    nomeusuario:{type:String, require:true},
    email:{type:String, unique:true, require:true},
    nomecompleto:{type:String , unique:true, require:true},
    telefone:{type:String},
    senha:{type:String, require:true},
    datacadastro:{type:Date, default:Date.now}
})

const Cliente = mongoose.model("usuario",schema)

module.exports = Cliente