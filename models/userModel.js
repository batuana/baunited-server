const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: [true, 'Please provide your email.'],
    lowercase: true, // transform the email into lowercase
    validate: [validator.isEmail, 'Please provide a valid email.'],
  },
  username: {
    type: String,
    unique: true,
    required: [true, 'Please provide a username.'],
  },
  name: {
    type: String,
    required: [true, 'Please tell us your name.'],
  },
  surname: {
    type: String,
    required: [true, 'Please tell us your surname.'],
  },
  birthDate: {
    type: Date,
    required: [true, 'Please tell us your birthdate.'],
  },
  photo: String,
  role: {
    type: String,
    enum: ['user', 'group-admin', 'admin'],
    default: 'user',
  },
  password: {
    type: String,
    required: [true, 'Please provide a password.'],
    minlength: 8,
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password.'],
    validate: {
      // NOTE this only works on save and create (when we create a new object)
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords are not the same.',
    },
  },
  passwordChangedAt: Date,
  active: {
    type: Boolean,
    default: true,
    select: false,
  },
});

// We're not doing query from the database where the model rules like select:false applies
userSchema.pre('save', async function (next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirm field to not to persist it in db, happens after the validation is already done
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000; // REVIEW to be certain
  next();
});

userSchema.pre(/^find/, function (next) {
  // NOTE this points to the current query
  this.find({ active: { $ne: false } });
  next();
});

// instance methods, available on all user documents
userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = this.passwordChangedAt.getTime() / 1000;

    return JWTTimestamp < changedTimestamp;
  }

  return false;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
