const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const Task = require('./task')

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        unique: true,
        required: true,
        trim: true,
        lowercase: true,
        validate(value) {
            if (!validator.isEmail(value)) {
                throw new Error('Email is invalid')
            }
        }
    },
    password: {
        type: String,
        required: true,
        minlength: 7,
        trim: true,
        validate(value) {
            if (value.toLowerCase().includes('password')) {
                throw new Error('Password cannot contain "password"')
            }
        }
    },
    age: {
        type: Number,
        default: 0,
        validate(value) {
            if (value < 0) {
                throw new Error('Age must be a postive number')
            }
        }
    },
    a_tokens: [{
        access_token: {
            type: String,
            required: true
        },
    }],
    r_tokens: [{
        refresh_token: {
            type: String,
            required: true
        }
    }]
    
    
})

userSchema.virtual('tasks', {
    ref: 'Task',
    localField: '_id',
    foreignField: 'owner'
})

userSchema.methods.toJSON = function () {
    const user = this
    const userObject = user.toObject()

    delete userObject.password
    delete userObject.a_tokens
    delete userObject.r_tokens

    return userObject
}


userSchema.methods.generateAccessToken = async function () {
    const user = this
    const access_token = jwt.sign({ _id: user._id.toString() }, 'accessTokenSecret' , {expiresIn : '2 m'})
  
    user.a_tokens = user.a_tokens.concat({ access_token })
    await user.save()

    return access_token
}


userSchema.methods.generateRefreshToken = async function () {
    const user = this
   
    const refresh_token = jwt.sign({ _id: user._id.toString() }, 'refreshTokenSecret' ,{expiresIn : '11 days'})
    user.r_tokens = user.r_tokens.concat({ refresh_token })
    await user.save()

    return refresh_token
}
/*

userSchema.methods.generateAccessToken = async (user) =>{
  //  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '11m'})
  console.log("We came here")
  const access_token= jwt.sign(user, "accessTokenSecret", {expiresIn: '11m'})
  user.a_tokens = user.a_tokens.concat({ access_token })
  await user.save()

  return access_token

}
userSchema.methods.generateRefreshToken = async (user) =>{
    console.log("We came here")  
  const refresh_token =jwt.sign(user, "refreshTokenSecret", {expiresIn: '7d'})
  user.r_tokens = user.r_tokens.concat({ access_token })
  await user.save()
  return refresh_token
}
*/


userSchema.statics.findByCredentials = async (email, password) => {
    const user = await User.findOne({ email })

    if (!user) {
        throw new Error('Unable to login')
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
        throw new Error('Unable to login')
    }

    return user
}

// Hash the plain text password before saving
userSchema.pre('save', async function (next) {
    const user = this

    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8)
    }

    next()
})

// Delete user tasks when user is removed
userSchema.pre('remove', async function (next) {
    const user = this
    await Task.deleteMany({ owner: user._id })
    next()
})

const User = mongoose.model('User', userSchema)

module.exports = User