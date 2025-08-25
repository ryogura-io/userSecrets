require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const saltRounds = 10;
const app = express();

// Setup
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SECRET || "MySessionSecret",
    resave: false,
    saveUninitialized: false
  })
);

// Initialize passport
app.use(passport.initialize());
app.use(passport.session());

// MongoDB Atlas Connection
const mongoURI = process.env.MONGO_URI;

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log("✅ Connected to MongoDB Atlas Cluster!");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
  });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secrets: [String]
});
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

// Passport config
// passport.use(User.createStrategy ? User.createStrategy() : null);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    async function (accessToken, refreshToken, profile, cb) {
      try {
        console.log("🔐 Google Profile received:");
        console.log({
          id: profile.id,
          name: profile.displayName,
          email: profile.emails?.[0]?.value,
          photo: profile.photos?.[0]?.value
        });

        const user = await User.findOrCreate(
          { googleId: profile.id },
          { email: profile.emails[0].value }
        );

        cb(null, user.doc);
      } catch (err) {
        cb(err);
      }
    }
  )
);


// Middleware
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

// Routes
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/register", (req, res) => {
  res.render("register", { message: null });
});

app.get("/login", (req, res) => {
  res.render("login", { message: null });
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

//show secrets on secrets.ejs
app.get("/secrets", async (req, res) => {
  try {
    const usersWithSecrets = await User.find({ secrets: { $exists: true, $ne: [] } });

    // Flatten the array of arrays into one list of all secrets
    const allSecrets = usersWithSecrets.flatMap(user => user.secrets);

    // ✅ Pass the secrets array to the EJS view
    res.render("secrets", { secrets: allSecrets });
  } catch (err) {
    console.error("❌ Failed to load secrets:", err);
    res.send("Failed to load secrets.");
  }
});


// Google Auth Routes
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/secrets");
  }
);

// Local Registration
app.post("/register", async (req, res) => {
  const { username: email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      const match = await bcrypt.compare(password, existingUser.password);
      if (match) {
        req.login(existingUser, (err) => {
          if (err) throw err;
          return res.redirect("/secrets");
        });
      } else {
        return res.render("register", {
          message: "An account with this email already exists, but the password is incorrect."
        });
      }
    } else {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const newUser = new User({ email, password: hashedPassword });
      await newUser.save();
      req.login(newUser, (err) => {
        if (err) throw err;
        return res.redirect("/secrets");
      });
    }
  } catch (err) {
    console.error(err);
    res.send("Error during registration.");
  }
});

// Local Login
app.post("/login", async (req, res) => {
  const { username: email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.render("login", {
        message: "No account found with this email. Please register."
      });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render("login", {
        message: "Incorrect password. Please try again."
      });
    }

    req.login(user, (err) => {
      if (err) throw err;
      return res.redirect("/secrets");
    });
  } catch (err) {
    console.error(err);
    res.send("Error during login.");
  }
});

//post upload
app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;

  try {
    const user = await User.findById(req.user.id);

    if (user) {
      if (!Array.isArray(user.secrets)) {
        user.secrets = []; // ✅ initialize if missing
      }

      user.secrets.push(submittedSecret);
      await user.save();

      console.log("✅ Secret saved!");
      res.redirect("/secrets");
    } else {
      res.redirect("/login");
    }
  } catch (err) {
    console.error("❌ Error saving secret:", err);
    res.send("Failed to save secret.");
  }
});



// Start Server
const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
