const express=require('express');
const router=express.Router(); //another way to define the routes
const bodyParser=require('body-parser');
const jwt=require('jsonwebtoken'); //its a way to generate and validate the tokens
const bcrypt=require('bcryptjs');
const config=require('../config');
const User=require('../modal/userSchema');
router.use(bodyParser.urlencoded({extended:true}));
router.use(bodyParser.json());

// get all user
router.get('/users',(req,res)=>{
    User.find({},(err,data)=>{
        if(err) throw err;
        res.send(data)
    })
})

// Register
router.post('/register',(req,res)=>{
    // encrypt password
let hashpassword=bcrypt.hashSync(req.body.password,8);
User.create({
    name:req.body.name,
    email:req.body.email,
    password:hashpassword,
    phone:req.body.phone,
    role:req.body.role?req.body.role:'User'
},(err,data)=>{
    if(err) throw err;
    res.status(200).send("Registration Successfull")
}) 

})
//login
router.post('/login',(req,res)=>{
    User.findOne({email:req.body.email},(err,user)=>{
        if(err) return res.status(500).send({auth:false,token:"Error while login"})
        if(!user) return res.status(200).send({auth:false,token:"No User Found Register first"}) //checking email
        else{
            const passIsvalid=bcrypt.compareSync(req.body.password,user.password) //checking password 
            if(!passIsvalid) return res.status(200).send({auth:false,token:'invalid'})
            // password and email is valid match generate token
            let token=jwt.sign({id:user._id},config.secret,{expiresIn:86400}) //86400 for 24 hoours
            res.status(200).send({auth:true,token:token})
        }
    })
})
//userinfo
router.get('/userInfo',(req,res)=>{
    let token= req.headers['x-access-token'];
    if(!token) res.send({auth:false,token:'No token Provided'})
    //token verified
    jwt.verify(token,config.secret,(err,user)=>{
        if(err) return res.status(200).send({auth:false,token:'Invalid Token'})
        User.findById(user.id,(err,result)=>{
            if(err) throw err;
            res.send(result)
        })
    })
})
//deleteUser
router.delete('/delete',(req,res)=>{
    User.remove({},(err,data)=>{
        if(err) throw err;
        res.send("userdeleted")
    })
})
module.exports=router;

