const fs = require('fs');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Post = require('../../models/postModel');
const User = require('../../models/userModel');
const Comment = require('../../models/commentModel');

dotenv.config({ path: './config.env' });

const DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);

mongoose
  .connect(DB)
  .then(con => {
    console.log('DB connection successful');
  })
  .catch(err => console.log(err));

// READ JSON FILE
// const posts = JSON.parse(fs.readFileSync(`${__dirname}/posts.json`, 'utf-8'));
const comments = JSON.parse(fs.readFileSync(`${__dirname}/comments.json`, 'utf-8'));

async function getAllPosts() {
  const dbPosts = await Post.find();
  const dbUsers = await User.find();

  for (let i = 0; i < comments.length; i++) {
    let previousIndex;
    for (const comment of comments[i]) {
      comment.post = dbPosts[i]._id;
      let currentIndex = Math.floor(Math.random() * 4);
      while (previousIndex !== undefined && currentIndex === previousIndex) {
        currentIndex = Math.floor(Math.random() * 4);
      }
      comment.user = dbUsers[currentIndex]._id; // [0, 1) => [0, 4) => [0, 3]
      previousIndex = currentIndex;
    }
  }
  fs.writeFileSync(`${__dirname}/comments.json`, JSON.stringify(comments));
  process.exit();
}

// getAllPosts();

// IMPORT DATA INTO DB
const importData = async () => {
  try {
    // await Post.create(posts);
    await Comment.create([].concat(...comments));
    console.log('Data successfully loaded!');
  } catch (err) {
    console.log(err);
  }
  process.exit();
};

// DELETE ALL DATA FROM COLLECTION
const deleteData = async () => {
  try {
    await Post.deleteMany();
    await Comment.deleteMany();
    console.log('Data successfully deleted!');
  } catch (err) {
    console.log(err);
  }
  process.exit();
};

if (process.argv[2] === '--import') {
  importData();
} else if (process.argv[2] === '--delete') {
  deleteData();
}

console.log(process.argv);
