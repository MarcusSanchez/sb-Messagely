const db = require("../db");
const ExpressError = require("../expressError");

class Message {

  static async create({ from_username, to_username, body }) {
    try {
      const result = await db.query(
        `INSERT INTO messages (
              from_username,
              to_username,
              body,
              sent_at)
            VALUES ($1, $2, $3, current_timestamp)
            RETURNING id, from_username, to_username, body, sent_at`,
        [from_username, to_username, body]
      );

      return result.rows[0];
    } catch (error) {
      throw new ExpressError("Failed to create message", 500);
    }
  }

  static async markRead(id) {
    try {
      const result = await db.query(
        `UPDATE messages
           SET read_at = current_timestamp
           WHERE id = $1
           RETURNING id, read_at`,
        [id]
      );

      if (!result.rows[0]) {
        throw new ExpressError(`No such message: ${id}`, 404);
      }

      return result.rows[0];
    } catch (error) {
      throw new ExpressError("Failed to mark message as read", 500);
    }
  }

  static async get(id) {
    try {
      const result = await db.query(
        `SELECT m.id,
                m.from_username,
                f.first_name AS from_first_name,
                f.last_name AS from_last_name,
                f.phone AS from_phone,
                m.to_username,
                t.first_name AS to_first_name,
                t.last_name AS to_last_name,
                t.phone AS to_phone,
                m.body,
                m.sent_at,
                m.read_at
          FROM messages AS m
            JOIN users AS f ON m.from_username = f.username
            JOIN users AS t ON m.to_username = t.username
          WHERE m.id = $1`,
        [id]
      );

      let m = result.rows[0];

      if (!m) {
        throw new ExpressError(`No such message: ${id}`, 404);
      }

      return {
        id: m.id,
        from_user: {
          username: m.from_username,
          first_name: m.from_first_name,
          last_name: m.from_last_name,
          phone: m.from_phone,
        },
        to_user: {
          username: m.to_username,
          first_name: m.to_first_name,
          last_name: m.to_last_name,
          phone: m.to_phone,
        },
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at,
      };
    } catch (error) {
      throw new ExpressError("Failed to retrieve message", 500);
    }
  }
}

module.exports = Message;
