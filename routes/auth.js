const router = require('express').Router();
const User = require('../model/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { registerValidation, loginValidation } = require('../validation');

router.post('/register', async (req,res) => { 
	//validation before create a user
	const { error } = registerValidation(req.body);
	if(error) return res.status(400).send(error.details[0].message);
	
	//cheking user is already in the db
	const emailExit = await User.findOne({email: req.body.email});
	if(emailExit) return res.status(400).send("Email alrerqdy exits");
	
	//hash password

	const salt = await bcrypt.genSalt(10);
	const hashpasswod = await bcrypt.hash(req.body.password, salt);

	const user = new User({
		name:req.body.name,
		email:req.body.email,
		password:hashpasswod
	});
	try{
		const savedUser = await user.save();
		res.send({ user: user._id });
	}catch(err){
		res.status(400).send(err);
			
	}
});

//LOGIN 
router.post('/login', async (req,res) => {
	//validation before create a user
	const { error } = loginValidation(req.body);
	if(error) return res.status(400).send(error.details[0].message);
	
	//cheking user is already in the db
	const user = await User.findOne({email: req.body.email});
	if(!user) return res.status(400).send("Email does not exits");
	
	//password is correct or not
	const validPass = await bcrypt.compare(req.body.password, user.password);
	if(!validPass) return res.status(400).send("Password is wrong");
	//create and assign token
	const token = jwt.sign({ _id:user.id}, process.env.TOKEN_SECRET);
	res.header('auth-token', token).send({ token:token });
	

});
module.exports = router;

