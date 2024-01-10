const db = require("../db");
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");
const { BCRYPT_WORK_FACTOR } = require("../config");

class User {
  static async register({ username, password, first_name, last_name, phone }) {
    try {
      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
      const result = await db.query(
        `INSERT INTO users (
            username,
            password,
            first_name,
            last_name,
            phone,
            join_at,
            last_login_at)
          VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
          RETURNING username, first_name, last_name, phone`,
        [username, hashedPassword, first_name, last_name, phone]
      );
      return result.rows[0];
    } catch (error) {
      throw new ExpressError("User registration failed", 500);
    }
  }

  static async authenticate(username, password) {
    try {
      const result = await db.query(
        "SELECT password FROM users WHERE username = $1",
        [username]
      );
      const user = result.rows[0];

      return user && (await bcrypt.compare(password, user.password));
    } catch (error) {
      throw new ExpressError("Authentication failed", 401);
    }
  }

  static async updateLoginTimestamp(username) {
    try {
      const result = await db.query(
        `UPDATE users
         SET last_login_at = current_timestamp
         WHERE username = $1
         RETURNING username`,
        [username]
      );

      if (!result.rows[0]) {
        throw new ExpressError(`No such user: ${username}`, 404);
      }
    } catch (error) {
      throw new ExpressError("Failed to update login timestamp", 500);
    }
  }

  static async all() {
    try {
      const result = await db.query(
        `SELECT username, first_name, last_name, phone
         FROM users
         ORDER BY username`
      );

      return result.rows;
    } catch (error) {
      throw new ExpressError("Failed to retrieve user list", 500);
    }
  }

  static async get(username) {
    try {
      const result = await db.query(
        `SELECT username, first_name, last_name, phone, join_at, last_login_at
         FROM users
         WHERE username = $1`,
        [username]
      );

      if (!result.rows[0]) {
        throw new ExpressError(`No such user: ${username}`, 404);
      }

      return result.rows[0];
    } catch (error) {
      throw new ExpressError("Failed to retrieve user information", 500);
    }
  }

  static async messagesFrom(username) {
    try {
      const result = await db.query(
        `SELECT m.id, m.to_username, u.first_name, u.last_name, u.phone,
                m.body, m.sent_at, m.read_at
         FROM messages AS m
         JOIN users AS u ON m.to_username = u.username
         WHERE from_username = $1`,
        [username]
      );

      return result.rows.map((m) => ({
        id: m.id,
        to_user: {
          username: m.to_username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone,
        },
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at,
      }));
    } catch (error) {
      throw new ExpressError("Failed to retrieve messages from user", 500);
    }
  }

  static async messagesTo(username) {
    try {
      const result = await db.query(
        `SELECT m.id, m.from_username, u.first_name, u.last_name, u.phone,
                m.body, m.sent_at, m.read_at
         FROM messages AS m
         JOIN users AS u ON m.from_username = u.username
         WHERE to_username = $1`,
        [username]
      );

      return result.rows.map((m) => ({
        id: m.id,
        from_user: {
          username: m.from_username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone,
        },
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at,
      }));
    } catch (error) {
      throw new ExpressError("Failed to retrieve messages to user", 500);
    }
  }
}

module.exports = User;