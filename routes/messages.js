const Router = require("express").Router;
const Message = require("../models/message");
const { ensureLoggedIn, ensureCorrectUser } = require("../middleware/auth");

const router = new Router();

/** GET /:id - Get detail of message.
 *
 * => {message: {id, body, sent_at, read_at, from_user: {username, first_name, last_name, phone}, to_user: {username, first_name, last_name, phone}}
 *
 * Ensure that the currently-logged-in user is either the to or from user.
 **/
router.get("/:id", ensureLoggedIn, async function(req, res, next) {
  try {
    const message = await Message.get(req.params.id);

    // Check if the logged-in user is either the sender or receiver of the message
    if (req.user.username === message.from_user.username || req.user.username === message.to_user.username) {
      return res.json({ message });
    } else {
      throw new ExpressError("Unauthorized", 403);
    }
  } catch (error) {
    return next(error);
  }
});

/** POST / - Post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 * Any logged-in user can send a message to any other user.
 **/
router.post("/", ensureLoggedIn, async function(req, res, next) {
  try {
    const { to_username, body } = req.body;
    const message = await Message.create({ from_username: req.user.username, to_username, body });
    return res.json({ message });
  } catch (error) {
    return next(error);
  }
});

/** POST/:id/read - Mark message as read.
 *
 *  => {message: {id, read_at}}
 *
 * Ensure that only the intended recipient can mark it as read.
 **/
router.post("/:id/read", ensureCorrectUser, async function(req, res, next) {
  try {
    const message = await Message.markRead(req.params.id);

    // Ensure that the logged-in user is the intended recipient of the message
    if (req.user.username === message.to_user.username) {
      return res.json({ message });
    } else {
      throw new ExpressError("Unauthorized", 403);
    }
  } catch (error) {
    return next(error);
  }
});

module.exports = router;