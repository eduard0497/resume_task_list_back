require("dotenv").config();
const cors = require("cors");
const express = require("express");
const knex = require("knex");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const app = express();

//
const corsOptions = () => {
  if (process.env.IS_DEV_MODE) {
    return {
      origin: ["http://localhost:3001"],
      credentials: true,
    };
  } else {
    return {
      origin: [process.env.FRONT_DOMAIN],
      credentials: true,
    };
  }
};
app.use(cors(corsOptions()));
app.use(express.json());
console.log("Cors Options");
console.log(corsOptions());

const configKnex = () => {
  if (process.env.IS_DEV_MODE) {
    return {
      client: "pg",
      connection: {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
      },
    };
  } else {
    return {
      client: "pg",
      connection: {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
        ssl: { rejectUnauthorized: false },
      },
    };
  }
};
const db = knex(configKnex());

//
//
const _SERVER_SIDE_ERROR_MESSAGE = "Server side error";
const _SERVER_SIDE_EMPTY_Strings_MESSAGE = "An empty value has been received";
//
const _DB_TABLE_USERS = "users";
const _DB_TABLE_CATEGORIES = "categories";
const _DB_TABLE_TASKS = "tasks";
//
const _TASK_STATUS_PENDING = "pending";
const _TASK_STATUS_FINISHED = "finished";

const verifyToken = (req, res, next) => {
  try {
    // const token = req.cookies.token;
    const { token } = req.body;
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.body.decoded_user_id = decodedToken.user_id;
    next();
  } catch (e) {
    res.json({
      status: 0,
      tokenError: true,
      msg: "User is not authorized",
    });
    // if (e.name === "TokenExpiredError") {
    //   console.log(e);
    //   res.json({
    //     status: 0,
    //     tokenError: true,
    //     msg: "Token expired",
    //   });
    // } else {
    //   console.log("Verify Token Error!!!");
    //   res.json({
    //     status: 0,
    //     tokenError: true,
    //     msg: "User is not authorized",
    //   });
    // }
  }
};

app.post("/register-user", (req, res) => {
  const { username, password, first_name, last_name } = req.body;

  if (!checkStrings(username, password, first_name, last_name)) {
    res.json({
      status: 0,
      msg: _SERVER_SIDE_EMPTY_Strings_MESSAGE,
    });
    return;
  }

  db(_DB_TABLE_USERS)
    .select("*")
    .where({
      username,
    })
    .then((data) => {
      if (!data.length) {
        let hash = bcrypt.hashSync(password, 8);
        db(_DB_TABLE_USERS)
          .returning("*")
          .insert({
            username,
            password: hash,
            first_name,
            last_name,
            account_created: new Date().toUTCString(),
          })
          .then((data) => {
            if (!data.length) {
              res.json({
                status: 0,
                msg: "Error occured while registering the user",
              });
            } else {
              res.json({
                status: 1,
                msg: "User has been registered successfully",
              });
            }
          });
      } else {
        res.json({
          status: 0,
          msg: "The username already exists",
        });
      }
    })
    .catch((e) => {
      console.log(e);
      res.json({
        status: 0,
        msg: _SERVER_SIDE_ERROR_MESSAGE,
      });
    });
});

app.post("/user-login", (req, res) => {
  const { username, password } = req.body;

  if (!checkStrings(username, password)) {
    res.json({
      status: 0,
      msg: _SERVER_SIDE_EMPTY_Strings_MESSAGE,
    });
    return;
  }

  try {
    db(_DB_TABLE_USERS)
      .select("*")
      .where({
        username,
      })
      .then((data) => {
        if (!data.length) {
          res.json({
            status: 0,
            msg: "No such username",
          });
        } else {
          let db_stored_password = data[0].password;
          if (!bcrypt.compareSync(password, db_stored_password)) {
            res.json({
              status: 0,
              msg: "Wrong password",
            });
          } else {
            const token = jwt.sign(
              { user_id: data[0].id },
              process.env.JWT_SECRET_KEY
            );
            // res.cookie("token", token, {
            //   httpOnly: true,
            //   maxAge: 24 * 60 * 60 * 1000,
            //   secure: true,
            //   sameSite: "None",
            // });
            res.json({
              status: 1,
              token,
              msg: "User Found",
            });
          }
        }
      });
  } catch (error) {
    console.log(error);
    res.json({
      status: 0,
      msg: _SERVER_SIDE_ERROR_MESSAGE,
    });
  }
});

app.post("/authorize-user-to-proceed", verifyToken, (req, res) => {
  res.json({
    status: 1,
    msg: "User authorized",
  });
});

app.post("/logout", verifyToken, (req, res) => {
  res.clearCookie("token");
  res.json({
    status: 1,
    msg: "Logged out successfully",
  });
});

app.post("/get-user-info", verifyToken, (req, res) => {
  const { decoded_user_id } = req.body;
  db(_DB_TABLE_USERS)
    .select("*")
    .where({
      id: decoded_user_id,
    })
    .then((data) => {
      if (!data.length) {
        res.json({
          status: 0,
          msg: _SERVER_SIDE_ERROR_MESSAGE,
        });
      } else if (data.length == 1) {
        res.json({
          status: 1,
          userInfo: data,
        });
      } else {
        res.json({
          status: 0,
          msg: _SERVER_SIDE_ERROR_MESSAGE,
        });
      }
    });
});

app.post("/add-category", verifyToken, (req, res) => {
  const { decoded_user_id, category } = req.body;

  db(_DB_TABLE_CATEGORIES)
    .returning("*")
    .insert({
      user_id: decoded_user_id,
      category,
    })
    .then((data) => {
      if (!data.length) {
        res.json({
          status: 0,
          msg: "Unable to add a category",
        });
      } else {
        db(_DB_TABLE_CATEGORIES)
          .select("*")
          .where({
            user_id: decoded_user_id,
          })
          .then((data) => {
            res.json({
              status: 1,
              categories: data,
            });
          });
      }
    })
    .catch((e) => {
      res.json({
        status: 0,
        msg: _SERVER_SIDE_ERROR_MESSAGE,
      });
    });
});

app.post("/get-categories", verifyToken, (req, res) => {
  const { decoded_user_id } = req.body;

  db(_DB_TABLE_CATEGORIES)
    .select("*")
    .where({
      user_id: decoded_user_id,
    })
    .then((data) => {
      res.json({
        status: 1,
        categories: data,
      });
    })
    .catch((e) => {
      res.json({
        status: 0,
        msg: _SERVER_SIDE_ERROR_MESSAGE,
      });
    });
});

app.delete("/delete-category", verifyToken, (req, res) => {
  const { decoded_user_id, id } = req.body;

  db(_DB_TABLE_CATEGORIES)
    .returning("*")
    .del()
    .where({
      id,
    })
    .then((data) => {
      if (!data.length) {
        res.json({
          status: 0,
          msg: "Unable to delete the category",
        });
      } else {
        db(_DB_TABLE_CATEGORIES)
          .select("*")
          .where({
            user_id: decoded_user_id,
          })
          .then((data) => {
            res.json({
              status: 1,
              categories: data,
            });
          });
      }
    })
    .catch((e) => {
      res.json({
        status: 0,
        msg: _SERVER_SIDE_ERROR_MESSAGE,
      });
    });
});

app.post("/add-task", verifyToken, (req, res) => {
  const { decoded_user_id, category_id, task, due } = req.body;

  db(_DB_TABLE_TASKS)
    .returning("*")
    .insert({
      user_id: decoded_user_id,
      category_id,
      task,
      status: _TASK_STATUS_PENDING,
      due: due === "" ? null : new Date(due).toISOString(),
    })
    .then((data) => {
      if (!data.length) {
        res.json({
          status: 0,
          msg: "Unable to add the task",
        });
      } else {
        db(_DB_TABLE_TASKS)
          .select("*")
          .where({
            user_id: decoded_user_id,
          })
          .orderBy("id")
          .then((data) => {
            res.json({
              status: 1,
              tasks: data,
            });
          });
      }
    })
    .catch((e) => {
      res.json({
        status: 0,
        msg: _SERVER_SIDE_ERROR_MESSAGE,
      });
    });
});

app.post("/get-tasks", verifyToken, (req, res) => {
  const { decoded_user_id } = req.body;

  db(_DB_TABLE_TASKS)
    .select("*")
    .where({
      user_id: decoded_user_id,
    })
    .orderBy("id")
    .then((data) => {
      res.json({
        status: 1,
        tasks: data,
      });
    })
    .catch((e) => {
      res.json({
        status: 0,
        msg: _SERVER_SIDE_ERROR_MESSAGE,
      });
    });
});

app.post("/complete-task", verifyToken, (req, res) => {
  const { decoded_user_id, id } = req.body;

  db(_DB_TABLE_TASKS)
    .returning("*")
    .update({
      status: _TASK_STATUS_FINISHED,
    })
    .where({
      id,
    })
    .then((data) => {
      if (!data.length) {
        res.json({
          status: 0,
          msg: "Unable to update the task",
        });
      } else {
        db(_DB_TABLE_TASKS)
          .select("*")
          .where({
            user_id: decoded_user_id,
          })
          .orderBy("id")
          .then((data) => {
            res.json({
              status: 1,
              tasks: data,
            });
          });
      }
    })
    .catch((e) => {
      res.json({
        status: 0,
        msg: _SERVER_SIDE_ERROR_MESSAGE,
      });
    });
});

app.delete("/delete-task", verifyToken, (req, res) => {
  const { decoded_user_id, id } = req.body;

  db(_DB_TABLE_TASKS)
    .returning("*")
    .del()
    .where({
      id,
    })
    .then((data) => {
      if (!data.length) {
        res.json({
          status: 0,
          msg: "Unable to delete the task",
        });
      } else {
        db(_DB_TABLE_TASKS)
          .select("*")
          .where({
            user_id: decoded_user_id,
          })
          .orderBy("id")
          .then((data) => {
            res.json({
              status: 1,
              tasks: data,
            });
          });
      }
    })
    .catch((e) => {
      res.json({
        status: 0,
        msg: _SERVER_SIDE_ERROR_MESSAGE,
      });
    });
});

app.post("/undo-task", verifyToken, (req, res) => {
  const { decoded_user_id, id } = req.body;

  db(_DB_TABLE_TASKS)
    .returning("*")
    .update({
      status: _TASK_STATUS_PENDING,
    })
    .where({
      id,
    })
    .then((data) => {
      if (!data.length) {
        res.json({
          status: 0,
          msg: "Unable to update the task",
        });
      } else {
        db(_DB_TABLE_TASKS)
          .select("*")
          .where({
            user_id: decoded_user_id,
          })
          .orderBy("id")
          .then((data) => {
            res.json({
              status: 1,
              tasks: data,
            });
          });
      }
    })
    .catch((e) => {
      res.json({
        status: 0,
        msg: _SERVER_SIDE_ERROR_MESSAGE,
      });
    });
});

app.post("/edit-task", verifyToken, (req, res) => {
  const { decoded_user_id, id, task, due } = req.body;

  db(_DB_TABLE_TASKS)
    .returning("*")
    .update({
      task,
      due: due === "" ? null : new Date(due).toISOString(),
    })
    .where({
      id,
    })
    .then((data) => {
      if (!data.length) {
        res.json({
          status: 0,
          msg: "Unable to edit the task",
        });
      } else {
        db(_DB_TABLE_TASKS)
          .select("*")
          .where({
            user_id: decoded_user_id,
          })
          .orderBy("id")
          .then((data) => {
            res.json({
              status: 1,
              tasks: data,
            });
          });
      }
    })
    .catch((e) => {
      res.json({
        status: 0,
        msg: _SERVER_SIDE_ERROR_MESSAGE,
      });
    });
});

//
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`APP IS RUNNING ON PORT ${PORT}`);
});

//
function checkStrings(...args) {
  for (let arg of args) {
    if (!arg && arg !== 0) {
      return false;
    }
  }
  return true;
}
