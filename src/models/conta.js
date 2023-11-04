const mongoose = require("../database/conexao")

const schema = new mongoose.Schema({
    nome_banco:{type:String, require:true},
    tipo_conta:{type:String, require:true},
    nome_titular:{type:String , unique:true, require:true},
    limite_cartao:{type:String, require:true},
    datacadastro:{type:Date, default:Date.now}
})

const Conta = mongoose.model("conta",schema)

module.exports = Conta