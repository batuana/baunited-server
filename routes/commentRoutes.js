const express = require("express");
const authController = require("../controllers/authController");
const commentController = require("../controllers/commentController");

const router = express.Router();

// Protect all routes after this middleware
router.use(authController.protect);

router.route("/").post(commentController.createComment);
router.get("/usercomments", commentController.getAllComments);

// FIXME prevent access from users that do not own the post
router
  .route("/:id")
  // .patch(commentController.updateComment)
  .patch(commentController.voteComment)
  .delete(commentController.deleteComment);

module.exports = router;
