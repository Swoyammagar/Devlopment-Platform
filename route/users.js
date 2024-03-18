const express = require("express")
const router= express.Router()

router.use(logger)

router.get('/',(req, res)=>{
    res.send("User List")
})
router.get('/new',(req, res)=>{
    res.render("users/new",{firstName: "test"})
})
router.post('/',(req, res)=>{
    res.send("Create new user")
})

router
    .route("/:id")
    .get((req, res)=>{
        console.log(req.user)
        res.send(`User get with id ${req.params.id}`)
    })
    .put((req, res)=>{
        res.send(`User update with id ${req.params.id}`)
    })
    .delete((req, res)=>{
        res.send(`User delete with id ${req.params.id}`)
    })

// const users=[{name: "Swoyam"},{name: "Amshu"}]
// router.param("id",(req,res,next,id)=>{
//     // console.log(id)
//     req.user=users[id]
//     next()
// })
function logger(req,res,next) {
    console.log(req.originalUrl)
}
module.exports= router