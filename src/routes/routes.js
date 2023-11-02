const express = require("express")
const bcrypt = require("bcrypt");
const gerartoken = require("../utils/gerartoken")
const verificartoken = require("../middleware/verificartoken")
const router = express.Router();
const Cliente = require("../models/cliente")
const config= require("../config/settings")
const jwt = require("jsonwebtoken")


router.get("/",(req,res)=>{
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ auth: false, message: 'No token provided.' });
    jwt.verify(token, process.env.JWT_KEY, function(err, decoded) {
        if (err) return res.status(500).json({ auth: false, message: 'Failed to authenticate token.' });

        Cliente.find().then((result)=>{
            res.status(200).send({output:`Ok`,payload:result})
        }).catch((error)=>res.status(500).send({output:`Erro ao processar o pedido`,err:error}))
    })
})


router.post("/insert",(req,res)=>{

    bcrypt.hash(req.body.senha,config.bcrypt_salt,(err,cripto)=>{
        if(err){
            return res.status(500).send({output:`Erro ao processar o cadastro`,error:err})
        }

        req.body.senha = cripto

    const dados = new Cliente(req.body);
    dados.save().then((result)=>{
        res.status(201).send({output:`Cadastrado`,payload:result})
    }).catch((error)=>res.status(400).send({output:`Não foi possível cadastrar`,err:error}))
  })
})


router.post("/login",(req,res)=>{
    const user = req.body.usuario
    const password = req.body.senha

    Cliente.findOne({nomeusuario:user}).then((result)=>{
        if(!result){
            return res.status(404).send({output:`Usuário não existe`})
        }
        bcrypt.compare(password,result.senha).then((rs)=>{
            if(!rs){
                return res.status(400).send({output:`Usuário ou senha incorreto`})
            }

            const token = gerartoken(result._id,result.nomeusuario,result.email)
            res.status(200).send({output:"Autenticado",token:token})
        })
        .catch((error)=>res.status(500).send({output:`Erro ao processar dados -> ${error}`}))
    }).catch((err)=>res.status(500).send({output:`Erro ao processar o login -> ${err}`}))
})


router.post("/newpassword",(req,res)=>{
    const user = req.body.usuario
    const oldPassword = req.body.senha_antiga
    const newPassword = req.body.senha_nova
    const repetNew = req.body.senha_repetida
    
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ auth: false, message: 'No token provided.' });
    jwt.verify(token, process.env.JWT_KEY, function(err, decoded) {
        if(newPassword != repetNew){
            return res.status(400).send({output:`Nova senha e sua repetição não correspondem`})
        }
    
        Cliente.findOne({nomeusuario:user}).then((result)=>{
            if(!result){
                return res.status(404).send({output:`Usuário não existe`})
            }
            bcrypt.compare(oldPassword,result.senha).then((rs)=>{
                if(!rs){
                    return res.status(400).send({output:`Usuário ou senha incorreto`})
                }
                Cliente.findByIdAndUpdate(result.id,senha = newPassword,{new:true}).then((result)=>{
                    if(!result){
                        res.status(400).send({output:`Não foi possível localizar`})
                    }
                    res.status(200).send({ouptut:`Atualizado`,payload:result})
                }).catch((error)=>res.status(500).send({output:`Erro ao tentar atualizar`,erro:error}))
            })
            .catch((error)=>res.status(500).send({output:`Erro ao processar dados -> ${error}`}))
        }).catch((err)=>res.status(500).send({output:`Erro ao processar o login -> ${err}`}))
    })
})


router.put("/update/:id",(req, res)=>{
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ auth: false, message: 'No token provided.' });
    jwt.verify(token, process.env.JWT_KEY, function(err, decoded) {
        Cliente.findByIdAndUpdate(req.params.id,req.body,{new:true}).then((result)=>{
            if(!result){
                res.status(400).send({output:`Não foi possível localizar`})
            }
            res.status(200).send({ouptut:`Atualizado`,payload:result})
        }).catch((error)=>res.status(500).send({output:`Erro ao tentar atualizar`,erro:error}))
    })
})

router.delete("/delete/:id",(req,res)=>{
    Cliente.findByIdAndDelete(req.params.id).then((result)=>{
        res.status(204).send({output:`Apagado`})
    }).catch((error)=>res.status(500).send({output:`Erro ao tentar apagar`,erro:error}))
})

router.use((req,res)=>{
    res.type("application/json");
    res.status(404).send({mensagem:"404 - Not Found"})
})

module.exports = router;