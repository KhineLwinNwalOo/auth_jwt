const router = require('express').Router();
const User = require('../model/User');
const { registerValidation } = require('../validation');

router.post('/register', async (req,res) => {
	const { error } = registerValidation(req.body);
	if(error) return res.status(400).send(error.details[0].message);
	
	//cheking user is already in the db
	const emailExit = await User.findOne({email: req.body.email});
	if(emailExit) return res.status(400).send("Email alrerqdy exits");


	const user = new User({
		name:req.body.name,
		email:req.body.email,
		password:req.body.password
	});
	try{
		const savedUser = await user.save();
		res.send(savedUser);
	}catch(err){
		
		res.status(400).send(err);
			
	}
});

module.exports = router;

