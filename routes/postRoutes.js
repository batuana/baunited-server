const express = require('express');
const authController = require('../controllers/authController');
const postController = require('../controllers/postController');

const router = express.Router();

// Protect all routes after this middleware
router.use(authController.protect);

router.route('/').get(postController.getAllPosts).post(postController.createPost);

router
  .route('/:id')
  .get(postController.getPost)
  // FIXME prevent access from users that do not own the post
  // .patch(postController.updatePost)
  .patch(postController.votePost)
  .delete(postController.deletePost);

module.exports = router;
